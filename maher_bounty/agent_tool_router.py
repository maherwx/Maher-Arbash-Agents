from __future__ import annotations

import json
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .active_testing import _dalfox_findings, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls


# Agents choose from fixed local tools. Requests never contain shell commands,
# executable paths, arbitrary flags, payloads, or new target hosts.
SUPPORTED_AGENT_TOOLS = {"hakrawler", "nuclei", "dalfox", "zap-baseline.py"}
MAX_AGENT_REQUESTS = 8
MAX_AGENT_TARGETS = 30
MAX_HAKRAWLER_ORIGINS = 2
MAX_ZAP_ORIGINS = 2


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


def _prior_coverage(active_testing: dict, known: set[str]) -> dict[str, set[str]]:
    covered = {"nuclei": set(), "dalfox": set(), "zap-baseline.py": set()}
    for run in active_testing.get("runs", []):
        if not isinstance(run, dict) or run.get("status") in {"missing", "skipped"}:
            continue
        tool = run.get("tool")
        command = run.get("command", [])
        if not isinstance(command, list):
            command = []
        if tool == "nuclei":
            covered["nuclei"].update(_read_target_file(command, "-l") & known)
        elif tool == "dalfox":
            if len(command) >= 3 and command[1] == "file":
                try:
                    covered["dalfox"].update(
                        set(Path(command[2]).read_text(encoding="utf-8", errors="ignore").splitlines()) & known
                    )
                except OSError:
                    pass
        elif tool == "zap-baseline.py":
            try:
                covered["zap-baseline.py"].add(command[command.index("-t") + 1])
            except (ValueError, IndexError):
                pass
    return covered


def run_agent_tool_requests(
    agent_results: list[dict],
    known_urls: list[str],
    out_dir: str | Path,
    *,
    scope: dict,
    active_testing: dict | None = None,
) -> dict:
    """Run bounded, allowlisted shell-backed tool follow-ups on scoped URLs.

    Model output selects a tool and exact known URL only. Hakrawler output is
    re-validated against scope before it can feed a one-pass Nuclei follow-up.
    """
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known)
    requests = _request_rows(agent_results)
    selected = {"hakrawler": [], "nuclei": [], "dalfox": [], "zap-baseline.py": []}
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
        in_scope, out_scope = filter_in_scope_urls(candidates, scope)
        eligible = []
        for url in in_scope:
            if url not in known:
                continue
            parsed = urlparse(url)
            if tool == "dalfox" and not parsed.query:
                continue
            if tool in {"nuclei", "dalfox"} and url in covered[tool]:
                decisions.append({"agent": row.get("agent"), "tool": tool, "target": url, "status": "skipped", "reason": "already_covered_in_base_scan"})
                continue
            if tool == "zap-baseline.py" and _origin(url) in covered[tool]:
                decisions.append({"agent": row.get("agent"), "tool": tool, "target": url, "status": "skipped", "reason": "origin_already_covered_in_base_scan"})
                continue
            dedupe_key = _origin(url) if tool in {"hakrawler", "zap-baseline.py"} else url
            if dedupe_key not in seen[tool] and target_budget > 0:
                seen[tool].add(dedupe_key)
                eligible.append(url)
                target_budget -= 1
        if out_scope or any(value not in known for value in candidates if value not in out_scope):
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "filtered",
                "out_of_scope_count": len(out_scope),
                "unknown_url_count": sum(1 for value in candidates if value not in known and value not in out_scope),
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
    hakrawler_origins = list(dict.fromkeys(_origin(url) for url in selected["hakrawler"] if _origin(url)))[:MAX_HAKRAWLER_ORIGINS]
    for index, origin in enumerate(hakrawler_origins, start=1):
        if not shutil.which("hakrawler"):
            runs.append({"tool": "hakrawler", "status": "missing", "target": origin, "reason": "agent-requested route discovery; binary not installed"})
            continue
        output = root / f"hakrawler-agent-{index}.txt"
        result = _exec(
            ["hakrawler", "-d", "2", "-timeout", "10"],
            timeout=45,
            output=output,
            input_text=origin + "\n",
        )
        result["target"] = origin
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

    zap_urls = list(dict.fromkeys(
        _origin(url) for url in selected["zap-baseline.py"]
        if _origin(url) and _origin(url) not in covered["zap-baseline.py"]
    ))[:MAX_ZAP_ORIGINS]
    for index, origin in enumerate(zap_urls, start=1):
        if shutil.which("zap-baseline.py"):
            output_json = root / f"zap-agent-followup-{index}.json"
            output_html = root / f"zap-agent-followup-{index}.html"
            runs.append(_exec([
                "zap-baseline.py", "-t", origin, "-m", "2", "-T", "30",
                "-J", str(output_json), "-r", str(output_html),
            ], timeout=180))
        else:
            runs.append({"tool": "zap-baseline.py", "status": "missing", "target": origin, "reason": "agent-requested ZAP baseline; binary not installed"})
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
