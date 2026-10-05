from __future__ import annotations

import json
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .active_testing import _dalfox_findings, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls


# Agents choose from fixed local tools. Requests never contain shell commands,
# executable paths, arbitrary flags, payloads, or new target hosts.
SUPPORTED_AGENT_TOOLS = {
    "hakrawler", "katana", "httpx", "nuclei", "dalfox", "zap-baseline.py",
    "nikto", "nmap", "tlsx", "whatweb", "wafw00f",
}
MAX_AGENT_REQUESTS = 8
MAX_AGENT_TARGETS = 30
MAX_HAKRAWLER_ORIGINS = 2
MAX_ZAP_ORIGINS = 2
MAX_FOLLOWUP_ORIGINS = 2

ORIGIN_TOOLS = {"hakrawler", "katana", "nikto", "zap-baseline.py", "whatweb", "wafw00f", "tlsx"}
HOST_TOOLS = {"nmap"}


def _coverage_key(tool: str, url: str) -> str:
    if tool in HOST_TOOLS:
        return (urlparse(url).hostname or "").lower()
    if tool in ORIGIN_TOOLS:
        return _origin(url)
    return url


def _request_rows(results: list[dict]) -> list[dict]:
    rows = []
    for result in results:
        requests = result.get("tool_requests", [])
        if not isinstance(requests, list):
            continue
        for request in requests:
            if isinstance(request, dict):
                rows.append({"agent": result.get("agent"), **request})
            if len(rows) >= MAX_AGENT_REQUESTS:
                return rows
    return rows


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _read_target_file(command: list[str], flag: str) -> set[str]:
    try:
        path = Path(command[command.index(flag) + 1])
        return {line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()}
    except (ValueError, IndexError, OSError):
        return set()


def _prior_coverage(active_testing: dict, known: set[str], tool_plan: dict | None = None) -> dict[str, set[str]]:
    covered = {tool: set() for tool in SUPPORTED_AGENT_TOOLS}
    run_rows = [
        *(active_testing.get("runs", []) if isinstance(active_testing, dict) else []),
        *((tool_plan or {}).get("runs", []) if isinstance(tool_plan, dict) else []),
    ]
    for run in run_rows:
        if not isinstance(run, dict) or run.get("status") in {"missing", "skipped"}:
            continue
        tool = str(run.get("tool") or "").strip().lower()
        if tool not in covered:
            continue
        command = run.get("command", [])
        if not isinstance(command, list):
            command = []
        targets = set()
        if tool == "nuclei":
            targets.update(_read_target_file(command, "-l"))
        elif tool == "dalfox":
            if len(command) >= 3 and command[1] == "file":
                try:
                    targets.update(Path(command[2]).read_text(encoding="utf-8", errors="ignore").splitlines())
                except OSError:
                    pass
        elif tool == "nmap":
            host = run.get("target")
            if not host and command:
                host = command[-1]
            if host:
                covered[tool].add(str(host).lower())
            continue
        else:
            target = run.get("target") or run.get("url")
            if not target:
                for flag in ("-u", "-h", "-t"):
                    try:
                        target = command[command.index(flag) + 1]
                        break
                    except (ValueError, IndexError):
                        pass
            if not target and tool in {"whatweb", "wafw00f"} and command:
                target = command[-1]
            if target:
                targets.add(str(target))
        for target in targets:
            if target in known or _origin(target):
                covered[tool].add(_coverage_key(tool, target))
    return covered

def run_agent_tool_requests(
    agent_results: list[dict],
    known_urls: list[str],
    out_dir: str | Path,
    *,
    scope: dict,
    active_testing: dict | None = None,
    tool_plan: dict | None = None,
    target_references: dict[str, str] | None = None,
) -> dict:
    """Run bounded, allowlisted shell-backed tool follow-ups on scoped URLs.

    Model output selects a tool and exact known URL only. Hakrawler output is
    re-validated against scope before it can feed a one-pass Nuclei follow-up.
    """
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known, tool_plan)
    requests = _request_rows(agent_results)
    selected = {tool: [] for tool in SUPPORTED_AGENT_TOOLS}
    decisions = []
    seen = {name: set() for name in selected}
    target_budget = MAX_AGENT_TARGETS

    for row in requests:
        tool = str(row.get("tool", "")).strip().lower()
        if tool not in SUPPORTED_AGENT_TOOLS:
            decisions.append({"agent": row.get("agent"), "tool": tool or None, "status": "rejected", "reason": "tool_not_allowlisted"})
            continue
        raw_targets = row.get("targets", [])
        if isinstance(raw_targets, str):
            raw_targets = [raw_targets]
        if not isinstance(raw_targets, list):
            raw_targets = []
        candidates = [value for value in raw_targets if isinstance(value, str)]
        raw_refs = row.get("target_refs", [])
        if isinstance(raw_refs, str):
            raw_refs = [raw_refs]
        if not isinstance(raw_refs, list):
            raw_refs = []
        resolved_refs = [
            (target_references or {}).get(ref)
            for ref in raw_refs if isinstance(ref, str)
        ]
        unknown_ref_count = sum(1 for value in resolved_refs if not value)
        candidates.extend(value for value in resolved_refs if value)
        in_scope, out_scope = filter_in_scope_urls(candidates, scope)
        eligible = []
        for url in in_scope:
            if url not in known:
                continue
            parsed = urlparse(url)
            if tool == "dalfox" and not parsed.query:
                continue
            if tool == "dalfox" and not parsed.query:
                continue
            if tool == "tlsx" and parsed.scheme.lower() != "https":
                continue
            coverage_key = _coverage_key(tool, url)
            if coverage_key and coverage_key in covered[tool]:
                decisions.append({"agent": row.get("agent"), "tool": tool, "target": url, "status": "skipped", "reason": "already_covered_in_base_scan"})
                continue
            dedupe_key = coverage_key or url
            if dedupe_key not in seen[tool] and target_budget > 0:
                seen[tool].add(dedupe_key)
                eligible.append(url)
                target_budget -= 1
        if unknown_ref_count or out_scope or any(value not in known for value in candidates if value not in out_scope):
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "filtered",
                "out_of_scope_count": len(out_scope),
                "unknown_url_count": sum(1 for value in candidates if value not in known and value not in out_scope),
                "unknown_target_ref_count": unknown_ref_count,
            })
        if eligible:
            selected[tool].extend(eligible)
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "queued",
                "target_count": len(eligible), "reason": str(row.get("reason", ""))[:300],
            })
        elif not out_scope and not any(
            item.get("tool") == tool and item.get("target") in candidates and item.get("reason") in {
                "already_covered_in_base_scan", "origin_already_covered_in_base_scan",
            } for item in decisions
        ):
            decisions.append({"agent": row.get("agent"), "tool": tool, "status": "skipped", "reason": "no_known_eligible_targets"})

    runs, findings = [], []
    new_crawl_urls = []

    # Agents can request deeper, complementary passes from the installed local
    # web toolkit. Each command is selected from fixed argv templates.
    for tool in ("httpx", "katana", "whatweb", "wafw00f", "nikto", "nmap", "tlsx"):
        targets = []
        seen_keys = set()
        for url in selected[tool]:
            key = _coverage_key(tool, url)
            if key and key not in seen_keys and key not in covered[tool]:
                seen_keys.add(key)
                targets.append(url)
        if not targets:
            continue
        if tool == "httpx":
            if not shutil.which(tool):
                runs.append({"tool": tool, "status": "missing", "reason": "agent-requested HTTP probe; binary not installed"})
                continue
            target_file = root / "httpx-followup-targets.txt"
            target_file.write_text("\\n".join(targets) + "\\n", encoding="utf-8")
            result = _exec([tool, "-l", str(target_file), "-json", "-silent", "-rate-limit", "3"], timeout=180)
            result["target_count"] = len(targets)
            runs.append(result)
            continue
        for index, scan_url in enumerate(targets[:MAX_FOLLOWUP_ORIGINS], start=1):
            if not shutil.which(tool):
                runs.append({"tool": tool, "status": "missing", "target": scan_url, "reason": "agent-requested tool; binary not installed"})
                continue
            if tool == "katana":
                command = [tool, "-u", scan_url, "-silent", "-d", "3", "-jc", "-fs", "fqdn"]
            elif tool == "whatweb":
                command = [tool, "-a", "1", "--no-errors", scan_url]
            elif tool == "wafw00f":
                command = [tool, scan_url]
            elif tool == "nikto":
                command = [tool, "-h", scan_url, "-nointeractive"]
            elif tool == "nmap":
                hostname = (urlparse(scan_url).hostname or "").lower()
                command = [tool, "-sV", "-Pn", "--top-ports", "100", hostname]
            else:  # TLSX; URL scope and HTTPS scheme are checked above.
                command = [tool, "-u", scan_url, "-silent", "-san", "-cn"]
            result = _exec(command, timeout=300)
            result["target"] = scan_url
            runs.append(result)
    hakrawler_urls = []
    seen_hakrawler_origins = set()
    for url in selected["hakrawler"]:
        origin = _origin(url)
        if origin and origin not in seen_hakrawler_origins:
            seen_hakrawler_origins.add(origin)
            hakrawler_urls.append(url)
    for index, scan_url in enumerate(hakrawler_urls[:MAX_HAKRAWLER_ORIGINS], start=1):
        if not shutil.which("hakrawler"):
            runs.append({"tool": "hakrawler", "status": "missing", "target": scan_url, "reason": "agent-requested route discovery; binary not installed"})
            continue
        output = root / f"hakrawler-agent-{index}.txt"
        result = _exec(
            ["hakrawler", "-d", "2", "-timeout", "10"],
            timeout=45,
            output=output,
            input_text=scan_url + "\n",
        )
        result["target"] = scan_url
        runs.append(result)
        if output.exists():
            lines = [line.strip() for line in output.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
            crawled, _ = filter_in_scope_urls(lines, scope)
            new_crawl_urls.extend(url for url in crawled if url not in known)

    new_crawl_urls = list(dict.fromkeys(new_crawl_urls))[:MAX_AGENT_TARGETS]
    # A crawler request is useful only if it produces fresh in-scope URLs.
    # Run Nuclei once over just those URLs, never over the base-scan inventory again.
    nuclei_urls = list(dict.fromkeys([
        *(url for url in selected["nuclei"] if url not in covered["nuclei"]),
        *new_crawl_urls,
    ]))
    if nuclei_urls:
        if shutil.which("nuclei"):
            target_file = root / "nuclei-followup-targets.txt"
            target_file.write_text("\n".join(nuclei_urls) + "\n", encoding="utf-8")
            output = root / "nuclei-followup.jsonl"
            run = _exec([
                "nuclei", "-l", str(target_file), "-jsonl",
                "-severity", "medium,high,critical",
                "-rate-limit", "3", "-concurrency", "2", "-timeout", "10",
                "-retries", "1", "-exclude-tags", "dos,intrusive",
                "-o", str(output),
            ], timeout=180)
            run["target_count"] = len(nuclei_urls)
            runs.append(run)
            findings.extend(_nuclei_findings(output))
        else:
            runs.append({"tool": "nuclei", "status": "missing", "reason": "agent-requested targeted follow-up; binary not installed"})

    dalfox_urls = list(dict.fromkeys(url for url in selected["dalfox"] if url not in covered["dalfox"]))
    if dalfox_urls:
        if shutil.which("dalfox"):
            target_file = root / "dalfox-followup-targets.txt"
            target_file.write_text("\n".join(dalfox_urls) + "\n", encoding="utf-8")
            output = root / "dalfox-followup.txt"
            runs.append(_exec(["dalfox", "file", str(target_file), "--silence"], timeout=180, output=output))
            findings.extend(_dalfox_findings(output, dalfox_urls[0]))
        else:
            runs.append({"tool": "dalfox", "status": "missing", "reason": "agent-requested XSS follow-up; binary not installed"})

    zap_targets = []
    seen_zap_origins = set()
    for url in selected["zap-baseline.py"]:
        origin = _origin(url)
        if origin and origin not in covered["zap-baseline.py"] and origin not in seen_zap_origins:
            seen_zap_origins.add(origin)
            zap_targets.append(url)
    for index, scan_url in enumerate(zap_targets[:MAX_ZAP_ORIGINS], start=1):
        if shutil.which("zap-baseline.py"):
            output_json = root / f"zap-agent-followup-{index}.json"
            output_html = root / f"zap-agent-followup-{index}.html"
            runs.append(_exec([
                "zap-baseline.py", "-t", scan_url, "-m", "2", "-T", "30",
                "-J", str(output_json), "-r", str(output_html),
            ], timeout=180))
        else:
            runs.append({"tool": "zap-baseline.py", "status": "missing", "target": scan_url, "reason": "agent-requested ZAP baseline; binary not installed"})
    return {
        "mode": "allowlisted_shell_tool_followups",
        "request_count": len(requests),
        "known_in_scope_url_count": len(known),
        "rejected_inventory_url_count": len(rejected),
        "new_in_scope_urls": new_crawl_urls,
        "coverage_reused": {tool: len(urls) for tool, urls in covered.items()},
        "decisions": decisions,
        "runs": runs,
        "findings": findings,
    }
