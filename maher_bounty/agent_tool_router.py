from __future__ import annotations

import json
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .active_testing import _dalfox_findings, _directory_discovery, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls


# Agents choose from fixed local tools. Requests never contain shell commands,
# executable paths, arbitrary flags, payloads, or new target hosts.
SUPPORTED_AGENT_TOOLS = {
    "hakrawler", "katana", "httpx", "nuclei", "dalfox", "zap-baseline.py",
    "nikto", "nmap", "tlsx", "whatweb", "wafw00f", "dnsx", "naabu", "ffuf", "gobuster",
    "subfinder", "assetfinder", "waybackurls", "gau", "alterx",
}
MAX_AGENT_REQUESTS = 20
MAX_AGENT_TARGETS = 30
MAX_HAKRAWLER_ORIGINS = 2
MAX_ZAP_ORIGINS = 2
MAX_FOLLOWUP_ORIGINS = 2

ORIGIN_TOOLS = {"hakrawler", "katana", "nikto", "zap-baseline.py", "whatweb", "wafw00f", "tlsx", "ffuf", "gobuster", "httpx"}
HOST_TOOLS = {"nmap", "naabu", "dnsx", "subfinder", "assetfinder", "waybackurls", "gau", "alterx"}


def _coverage_key(tool: str, url: str) -> str:
    if tool in HOST_TOOLS:
        parsed = urlparse(url if "://" in url else "//" + url)
        return (parsed.hostname or url).lower()
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
        *((tool_plan or {}).get("metadata_runs", []) if isinstance(tool_plan, dict) else []),
    ]
    for run in run_rows:
        if not isinstance(run, dict) or run.get("status") != "ok":
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
        elif tool == "httpx":
            targets.update(
                entry if "://" in entry else "https://" + entry
                for entry in _read_target_file(command, "-l")
            )
        elif tool == "dalfox":
            if len(command) >= 3 and command[1] == "file":
                try:
                    targets.update(Path(command[2]).read_text(encoding="utf-8", errors="ignore").splitlines())
                except OSError:
                    pass
        elif tool in HOST_TOOLS:
            host = run.get("target")
            if not host:
                for flag in ("-host", "-d"):
                    try:
                        host = command[command.index(flag) + 1]
                        break
                    except (ValueError, IndexError):
                        pass
            if not host and command:
                host = command[-1]
            if host:
                covered[tool].add(str(host).lower())
            continue
        else:
            target = run.get("target") or run.get("url")
            if not target:
                for flag in ("-u", "-h", "-t", "-d"):
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


def build_local_tool_requests(
    known_urls: list[str],
    *,
    scope: dict,
    active_testing: dict | None = None,
    tool_plan: dict | None = None,
) -> dict:
    """Build a no-model local follow-up plan from evidence and actual coverage.

    This lets the coordinator keep running specialist tools when no local
    inference runtime is configured. It only chooses allowlisted binaries and
    exact in-scope URLs already present in inventory or captured traffic.
    """
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known, tool_plan)
    origin_urls = []
    seen_origins = set()
    for url in allowed:
        origin = _origin(url)
        if origin and origin not in seen_origins:
            seen_origins.add(origin)
            origin_urls.append(url)

    candidates_by_tool = {
        "nuclei": allowed,
        "dalfox": [url for url in allowed if urlparse(url).query],
        "katana": origin_urls,
        "hakrawler": allowed,
        "zap-baseline.py": origin_urls,
        "naabu": origin_urls,
        "dnsx": origin_urls,
        "alterx": origin_urls,
        "nmap": origin_urls,
        "tlsx": [url for url in origin_urls if urlparse(url).scheme.lower() == "https"],
        "whatweb": origin_urls,
        "wafw00f": origin_urls,
        "nikto": origin_urls,
        "httpx": origin_urls,
        "subfinder": origin_urls,
        "assetfinder": origin_urls,
        "waybackurls": origin_urls,
        "gau": origin_urls,
    }
    # Choose one content-discovery engine to avoid duplicate wordlist traffic.
    dir_tool = "ffuf" if shutil.which("ffuf") else "gobuster"
    candidates_by_tool[dir_tool] = [
        url for url in origin_urls
        if urlparse(url).path in {"", "/"} and not urlparse(url).query
    ]

    requests = []
    selected_targets = set()
    for tool in (
        "nuclei", "dalfox", "katana", "hakrawler", "zap-baseline.py",
        "naabu", "dnsx", "alterx", "tlsx", "ffuf", "gobuster",
        "whatweb", "wafw00f", "nikto", "nmap", "httpx",
        "subfinder", "assetfinder", "waybackurls", "gau",
    ):
        if tool not in candidates_by_tool or len(requests) >= MAX_AGENT_REQUESTS:
            continue
        eligible = []
        seen_keys = set()
        for url in candidates_by_tool[tool]:
            key = _coverage_key(tool, url)
            if not key or key in covered[tool] or key in seen_keys:
                continue
            if tool == "dalfox" and not urlparse(url).query:
                continue
            if tool == "tlsx" and urlparse(url).scheme.lower() != "https":
                continue
            if tool in {"ffuf", "gobuster"} and urlparse(url).path not in {"", "/"}:
                continue
            seen_keys.add(key)
            eligible.append(url)
            if len(eligible) >= min(MAX_AGENT_TARGETS, 8):
                break
        if eligible:
            requests.append({
                "agent": "local_deterministic_coordinator",
                "tool_requests": [{
                    "tool": tool,
                    "targets": eligible,
                    "reason": "local evidence-driven coverage gap; no repeated successful base coverage",
                }],
            })
            selected_targets.update(eligible)
    return {
        "agent_results": requests,
        "request_count": len(requests),
        "known_in_scope_url_count": len(known),
        "rejected_inventory_url_count": len(rejected),
        "covered_tool_count": sum(bool(value) for value in covered.values()),
        "mode": "local_deterministic_evidence_coordinator",
    }


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
    for tool in ("httpx", "katana", "whatweb", "wafw00f", "nikto", "nmap", "tlsx", "dnsx", "naabu", "subfinder", "assetfinder", "waybackurls", "gau", "alterx"):
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
            target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
            result = _exec([tool, "-l", str(target_file), "-json", "-silent", "-rate-limit", "3"], timeout=180)
            result["target_count"] = len(targets)
            runs.append(result)
            continue
        for index, scan_url in enumerate(targets[:MAX_FOLLOWUP_ORIGINS], start=1):
            if not shutil.which(tool):
                runs.append({"tool": tool, "status": "missing", "target": scan_url, "reason": "agent-requested tool; binary not installed"})
                continue
            hostname = (urlparse(scan_url).hostname or "").lower()
            if tool == "alterx":
                command = [tool, "-silent", "-limit", "200"]
                generated_file = root / f"alterx-followup-{index}.txt"
                result = _exec(command, timeout=120, output=generated_file, input_text=hostname + "\n")
                result["target"] = scan_url
                runs.append(result)
                generated_hosts = [
                    line.strip() for line in generated_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip()
                ] if generated_file.exists() else []
                candidate_urls = ["https://" + host for host in generated_hosts]
                scoped_candidates, _ = filter_in_scope_urls(candidate_urls, scope)
                scoped_hosts = list(dict.fromkeys(urlparse(url).hostname or "" for url in scoped_candidates))
                scoped_hosts = [host for host in scoped_hosts if host]
                if scoped_hosts and shutil.which("dnsx"):
                    dns_output = root / f"alterx-dnsx-{index}.txt"
                    dns_result = _exec(
                        ["dnsx", "-silent", "-a", "-resp"], timeout=180, output=dns_output,
                        input_text="\n".join(scoped_hosts) + "\n",
                    )
                    dns_result["target"] = scan_url
                    runs.append(dns_result)
                    resolved_hosts = set()
                    if dns_output.exists():
                        for line in dns_output.read_text(encoding="utf-8", errors="ignore").splitlines():
                            host = line.strip().split(maxsplit=1)[0] if line.strip() else ""
                            if host in scoped_hosts:
                                resolved_hosts.add(host)
                    if resolved_hosts and shutil.which("httpx"):
                        probe_file = root / f"alterx-httpx-{index}-targets.txt"
                        probe_file.write_text("\n".join("https://" + host for host in sorted(resolved_hosts)) + "\n", encoding="utf-8")
                        http_output = root / f"alterx-httpx-{index}.jsonl"
                        http_result = _exec(
                            ["httpx", "-l", str(probe_file), "-json", "-silent", "-rate-limit", "3"],
                            timeout=180, output=http_output,
                        )
                        http_result["target"] = scan_url
                        runs.append(http_result)
                        if http_output.exists():
                            for line in http_output.read_text(encoding="utf-8", errors="ignore").splitlines():
                                try:
                                    data = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                found = data.get("url") or data.get("input") or data.get("host")
                                if isinstance(found, str):
                                    allowed_found, _ = filter_in_scope_urls([found], scope)
                                    new_crawl_urls.extend(url for url in allowed_found if url not in known)
                continue
            if tool in {"subfinder", "assetfinder", "waybackurls", "gau"}:
                if tool == "subfinder":
                    command = [tool, "-silent", "-d", hostname]
                elif tool == "assetfinder":
                    command = [tool, "--subs-only", hostname]
                elif tool == "waybackurls":
                    command = [tool, hostname]
                else:
                    command = [tool, "--subs", hostname]
                output = root / f"{tool}-followup-{index}.txt"
                result = _exec(command, timeout=240, output=output)
                result["target"] = scan_url
                runs.append(result)
                if output.exists():
                    lines = [line.strip() for line in output.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
                    candidates = ["https://" + line for line in lines] if tool in {"subfinder", "assetfinder"} else lines
                    scoped, _ = filter_in_scope_urls(candidates, scope)
                    new_crawl_urls.extend(url for url in scoped if url not in known)
                continue
            if tool == "dnsx":
                command = [tool, "-silent", "-a", "-resp"]
                result = _exec(command, timeout=180, input_text=hostname + "\n")
                result["target"] = scan_url
                runs.append(result)
                continue
            elif tool == "naabu":
                hostname = (urlparse(scan_url).hostname or "").lower()
                command = [tool, "-host", hostname, "-top-ports", "100", "-rate", "10", "-silent"]
            elif tool == "katana":
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
    for tool in ("ffuf", "gobuster"):
        for index, scan_url in enumerate(selected[tool][:MAX_FOLLOWUP_ORIGINS], start=1):
            if not shutil.which(tool):
                runs.append({"tool": tool, "status": "missing", "target": scan_url, "reason": "agent-requested directory tool; binary not installed"})
                continue
            content_runs = []
            new_urls = _directory_discovery(
                scan_url, root / f"{tool}-{index}", content_runs, preferred_tool=tool
            )
            for run in content_runs:
                run["target"] = scan_url
                runs.append(run)
            filtered, _ = filter_in_scope_urls(new_urls, scope)
            new_crawl_urls.extend(url for url in filtered if url not in known)

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
