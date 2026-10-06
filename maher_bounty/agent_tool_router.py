from __future__ import annotations

import json
import hashlib
import shutil
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

from .active_testing import _dalfox_findings, _directory_discovery, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls
from .zap_cli import run_zap_baseline
from .browser_xss import run_browser_xss


# Agents choose from fixed local tools. Requests never contain shell commands,
# executable paths, arbitrary flags, payloads, or new target hosts.
SUPPORTED_AGENT_TOOLS = {
    "browser-xss", "browser-xss-auth",
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


def _request_rows(results: list[dict], limit=MAX_AGENT_REQUESTS) -> list[dict]:
    # Share the request budget across roles, including repeated packets from
    # the same role. A request cannot impersonate another agent.
    queues = {}
    for result in results[:120]:
        if not isinstance(result, dict):
            continue
        requests = result.get("tool_requests", [])
        if not isinstance(requests, list):
            continue
        agent = result.get("agent")
        agent = agent[:128] if isinstance(agent, str) and agent else "unknown"
        queue = queues.setdefault(agent, deque())
        for request in requests[:MAX_AGENT_REQUESTS]:
            if isinstance(request, dict) and len(queue) < MAX_AGENT_REQUESTS:
                queue.append({**request, "agent": agent})
    rows = []
    while len(rows) < limit:
        progressed = False
        for queue in queues.values():
            if queue:
                rows.append(queue.popleft())
                progressed = True
            if len(rows) == limit:
                break
        if not progressed:
            break
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


def _prior_coverage(active_testing: dict, known: set[str], tool_plan: dict | None = None,
                    browser_xss_profile: dict | None = None) -> dict[str, set[str]]:
    covered = {tool: set() for tool in SUPPORTED_AGENT_TOOLS}
    run_rows = [
        *(active_testing.get("runs", []) if isinstance(active_testing, dict) else []),
        *((tool_plan or {}).get("runs", []) if isinstance(tool_plan, dict) else []),
        *((tool_plan or {}).get("metadata_runs", []) if isinstance(tool_plan, dict) else []),
    ]
    # Failed, blocked, missing, and timed-out runs count as attempts too.
    # A later run can retry after the recorded cause is fixed.
    attempted_statuses = {"ok", "nonzero", "timeout", "blocked", "missing", "partial"}
    for run in run_rows:
        if not isinstance(run, dict) or run.get("status") not in attempted_statuses:
            continue
        tool = str(run.get("tool") or "").strip().lower()
        if tool not in covered:
            continue
        command = run.get("command", [])
        if not isinstance(command, list):
            command = []
        targets = set()
        if tool in {"browser-xss", "browser-xss-auth"}:
            if tool == "browser-xss-auth" and (browser_xss_profile is None
                    or run.get("profile_sha256") != browser_xss_profile.get("profile_sha256")):
                continue
            covered[tool].update(url for url in known if hashlib.sha256(url.encode()).hexdigest() == run.get("target_sha256"))
            continue
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
                covered[tool].add(_coverage_key(tool, str(host)))
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
    browser_xss_profile: dict | None = None,
) -> dict:
    """Build a no-model local follow-up plan from evidence and actual coverage.

    This lets the coordinator keep running specialist tools when no local
    inference runtime is configured. It only chooses allowlisted binaries and
    exact in-scope URLs already present in inventory or captured traffic.
    """
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known, tool_plan, browser_xss_profile)
    origin_urls = []
    seen_origins = set()
    for url in allowed:
        origin = _origin(url)
        if origin and origin not in seen_origins:
            seen_origins.add(origin)
            origin_urls.append(url)

    candidates_by_tool = {
        "browser-xss-auth": [url for url in allowed if urlparse(url).query
                             and browser_xss_profile is not None
                             and _origin(url) == _origin(browser_xss_profile["identity"]["origin"])],
        "browser-xss": [url for url in allowed if urlparse(url).query],
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
        "browser-xss-auth", "nuclei", "dalfox", "browser-xss", "katana", "hakrawler", "zap-baseline.py",
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
    browser_xss_profile: dict | None = None,
) -> dict:
    """Run bounded, allowlisted shell-backed tool follow-ups on scoped URLs.

    Model output or the deterministic local coordinator selects allowlisted
    tools and exact known URLs. Discovered output is re-validated against scope
    before it can feed downstream validators.
    """
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known, tool_plan, browser_xss_profile)
    request_pool = _request_rows(agent_results, limit=120 * MAX_AGENT_REQUESTS)
    requests = request_pool[:MAX_AGENT_REQUESTS]
    deferred = [{"agent": row["agent"], "tool_requests": [{
        key: value for key, value in row.items() if key in {"tool", "targets", "target_refs", "reason"}
    }]} for row in request_pool[MAX_AGENT_REQUESTS:]]
    selected = {tool: [] for tool in SUPPORTED_AGENT_TOOLS}
    decisions = []
    seen = {name: set() for name in selected}
    target_budget = MAX_AGENT_TARGETS
    deferred_seen = {name: set() for name in selected}

    for row in requests:
        tool = str(row.get("tool", "")).strip().lower()
        if tool in {"zap", "zaproxy", "zap.sh"}:
            tool = "zap-baseline.py"
        if tool not in SUPPORTED_AGENT_TOOLS:
            decisions.append({"agent": row.get("agent"), "tool": tool or None, "status": "rejected", "reason": "tool_not_allowlisted"})
            continue
        if tool == "browser-xss-auth" and browser_xss_profile is None:
            decisions.append({"agent": row.get("agent"), "tool": tool, "status": "rejected",
                              "reason": "supplied_browser_identity_profile_required"})
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
        postponed = []
        capacity = MAX_AGENT_TARGETS if tool in {"httpx", "nuclei", "dalfox"} else MAX_FOLLOWUP_ORIGINS
        for url in in_scope:
            if url not in known:
                continue
            parsed = urlparse(url)
            if tool in {"dalfox", "browser-xss", "browser-xss-auth"} and not parsed.query:
                continue
            if tool == "browser-xss-auth" and _origin(url) != _origin(browser_xss_profile["identity"]["origin"]):
                continue
            if tool == "tlsx" and parsed.scheme.lower() != "https":
                continue
            coverage_key = _coverage_key(tool, url)
            if coverage_key and coverage_key in covered[tool]:
                decisions.append({"agent": row.get("agent"), "tool": tool, "target": url, "status": "skipped", "reason": "already_covered_in_base_scan"})
                continue
            dedupe_key = coverage_key or url
            if dedupe_key in seen[tool]:
                continue
            if target_budget > 0 and len(selected[tool]) + len(eligible) < capacity:
                seen[tool].add(dedupe_key)
                eligible.append(url)
                target_budget -= 1
            elif dedupe_key not in deferred_seen[tool]:
                deferred_seen[tool].add(dedupe_key)
                postponed.append(url)
        if postponed:
            deferred.append({"agent": row.get("agent"), "tool_requests": [{
                "tool": tool, "targets": postponed, "reason": "deferred by round execution budget"}]})
            decisions.append({"agent": row.get("agent"), "tool": tool, "status": "deferred",
                              "target_count": len(postponed), "reason": "round_execution_budget"})
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
        elif not postponed and not out_scope and not any(
            item.get("tool") == tool and item.get("target") in candidates and item.get("reason") in {
                "already_covered_in_base_scan", "origin_already_covered_in_base_scan",
            } for item in decisions
        ):
            decisions.append({"agent": row.get("agent"), "tool": tool, "status": "skipped", "reason": "no_known_eligible_targets"})

    runs, findings = [], []
    new_crawl_urls = []
    for index, scan_url in enumerate(selected["browser-xss-auth"][:MAX_FOLLOWUP_ORIGINS], start=1):
        check = run_browser_xss(scan_url, root / f"browser-xss-auth-{index}", scope=scope,
                                authorized=True, profile=browser_xss_profile)
        findings.extend(check.get("findings", []))
        runs.append({key: value for key, value in check.items() if key != "findings"} | {
            "target_sha256": hashlib.sha256(scan_url.encode()).hexdigest()})
    for index, scan_url in enumerate(selected["browser-xss"][:MAX_FOLLOWUP_ORIGINS], start=1):
        check = run_browser_xss(scan_url, root / f"browser-xss-{index}", scope=scope, authorized=True)
        findings.extend(check.get("findings", []))
        runs.append({key: value for key, value in check.items() if key != "findings"} | {
            "target_sha256": hashlib.sha256(scan_url.encode()).hexdigest()})

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
                command = [tool, "-u", scan_url, "-silent", "-json"]
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
        runs.append(run_zap_baseline(scan_url, root, scope, _exec))
    deferred_by_agent = {}
    for row in deferred:
        deferred_by_agent.setdefault(row["agent"], []).extend(row["tool_requests"])
    # Preserve one result packet per role so the next round's packet limit
    # cannot silently drop a long list of deferred single-request packets.
    deferred = [{"agent": agent, "tool_requests": rows} for agent, rows in deferred_by_agent.items()]
    return {
        "mode": "allowlisted_shell_tool_followups",
        "request_scheduling": "round_robin_by_role",
        "requesting_agent_count": len({row["agent"] for row in requests}),
        "deferred_requests": deferred,
        "attempted_targets": [{"tool": tool, "target": url} for tool, urls in selected.items() for url in urls]
                             + [{"tool": "nuclei", "target": url} for url in new_crawl_urls],
        "request_count": len(requests),
        "known_in_scope_url_count": len(known),
        "rejected_inventory_url_count": len(rejected),
        "new_in_scope_urls": new_crawl_urls,
        "coverage_reused": {tool: len(urls) for tool, urls in covered.items()},
        "decisions": decisions,
        "runs": runs,
        "findings": findings,
    }
