from __future__ import annotations

import ipaddress
import json
import hashlib
import shutil
import secrets
from collections import deque
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from .active_testing import _dalfox_findings, _directory_discovery, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls
from .zap_cli import run_zap_baseline
from .browser_xss import run_browser_xss


# Agents choose from fixed local tools. Requests never contain shell commands,
# executable paths, arbitrary flags, payloads, or new target hosts.
SUPPORTED_AGENT_TOOLS = {
    "browser-xss", "browser-xss-auth",
    "hakrawler", "katana", "httpx", "nuclei", "dalfox", "zap-baseline.py", "sslscan",
    "nikto", "nmap", "tlsx", "whatweb", "wafw00f", "dnsx", "naabu", "ffuf", "gobuster",
    "subfinder", "assetfinder", "waybackurls", "gau", "alterx", "arjun",
}
DIRECT_AGENT_TOOLS = SUPPORTED_AGENT_TOOLS - {"browser-xss-auth"}
AGENT_TOOL_PROFILES = {
    "all": DIRECT_AGENT_TOOLS,
    "web": {"browser-xss", "hakrawler", "katana", "httpx", "nuclei", "dalfox", "arjun",
            "zap-baseline.py", "nikto", "whatweb", "wafw00f", "ffuf", "gobuster"},
    "discovery": {"hakrawler", "katana", "httpx", "ffuf", "gobuster", "subfinder",
                  "assetfinder", "waybackurls", "gau", "alterx", "dnsx", "arjun"},
    "network": {"nmap", "naabu", "dnsx", "tlsx", "sslscan"},
}
MAX_AGENT_REQUESTS = 20
MAX_AGENT_TARGETS = 30
MAX_HAKRAWLER_ORIGINS = 2
MAX_ZAP_ORIGINS = 2
MAX_FOLLOWUP_ORIGINS = 2
MAX_ARJUN_TARGETS = 2
MAX_ARJUN_PARAMETERS_PER_URL = 30
MAX_ARJUN_JSON_BYTES = 2 * 1024 * 1024

ORIGIN_TOOLS = {"hakrawler", "katana", "nikto", "zap-baseline.py", "whatweb", "wafw00f", "tlsx", "ffuf", "gobuster", "httpx", "sslscan"}
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


def _http_probe_inventory(path, scope, known):
    """Admit only recorded HTTPX response URLs; no inferred hosts or paths."""
    urls, seen = [], set(known)
    telemetry = {"response_count": 0, "rejected_probe_url_count": 0,
                 "invalid_probe_row_count": 0, "probe_inventory_truncated": False}
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
    except OSError:
        return [], {**telemetry, "probe_inventory_status": "unavailable"}
    if len(raw) > 8 * 1024 * 1024:
        raw = raw[:8 * 1024 * 1024]
        telemetry["probe_inventory_truncated"] = True
    for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines()):
        if index >= 1000:
            telemetry["probe_inventory_truncated"] = True
            break
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            telemetry["invalid_probe_row_count"] += 1
            continue
        if (not isinstance(row, dict) or type(row.get("status_code")) is not int
                or not 100 <= row["status_code"] <= 599 or row.get("failed")):
            telemetry["invalid_probe_row_count"] += 1
            continue
        url = row.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            telemetry["invalid_probe_row_count"] += 1
            continue
        telemetry["response_count"] += 1
        try:
            allowed, rejected = filter_in_scope_urls([url], scope)
        except ValueError:
            allowed, rejected = [], [url]
        telemetry["rejected_probe_url_count"] += len(rejected)
        for value in allowed:
            if value not in seen:
                seen.add(value)
                urls.append(value)
    telemetry["new_in_scope_url_count"] = len(urls)
    telemetry["probe_inventory_status"] = ("partial" if telemetry["probe_inventory_truncated"]
                                            or telemetry["invalid_probe_row_count"] else "parsed")
    return urls, telemetry


def _arjun_parameter_urls(path, source_url: str, scope: dict, known: set[str]) -> tuple[list[str], dict]:
    """Extract bounded GET parameter names and bind them to the exact probed route."""
    telemetry = {
        "parameter_discovery_status": "unavailable",
        "parameter_artifact_complete": False,
        "parameter_endpoint_count": 0,
        "discovered_parameter_count": 0,
        "new_parameterized_url_count": 0,
        "invalid_parameter_row_count": 0,
        "out_of_scope_parameter_url_count": 0,
    }
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_ARJUN_JSON_BYTES + 1)
    except OSError:
        telemetry["parameter_discovery_status"] = "result_file_missing"
        return [], telemetry
    if len(raw) > MAX_ARJUN_JSON_BYTES:
        telemetry["parameter_discovery_status"] = "result_file_too_large"
        return [], telemetry
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        telemetry["parameter_discovery_status"] = "invalid_json"
        return [], telemetry
    if not isinstance(payload, dict):
        telemetry["parameter_discovery_status"] = "invalid_result_shape"
        return [], telemetry

    source = urlsplit(source_url)
    source_path = source.path or "/"
    existing_pairs = parse_qsl(source.query, keep_blank_values=True)
    existing_names = {name.casefold() for name, _ in existing_pairs}
    found_names = []
    seen_names = set(existing_names)
    for endpoint, details in list(payload.items())[:100]:
        if not isinstance(endpoint, str) or not isinstance(details, dict):
            telemetry["invalid_parameter_row_count"] += 1
            continue
        try:
            candidate = urlsplit(endpoint)
            same_origin = _origin(endpoint) == _origin(source_url)
        except ValueError:
            telemetry["invalid_parameter_row_count"] += 1
            continue
        if (not same_origin or (candidate.path or "/") != source_path
                or str(details.get("method", "")).upper() != "GET"):
            telemetry["invalid_parameter_row_count"] += 1
            continue
        telemetry["parameter_endpoint_count"] += 1
        params = details.get("params")
        if not isinstance(params, list):
            telemetry["invalid_parameter_row_count"] += 1
            continue
        for name in params[:MAX_ARJUN_PARAMETERS_PER_URL]:
            if (not isinstance(name, str) or not name or len(name) > 128
                    or any(ord(char) < 32 or ord(char) == 127 for char in name)):
                telemetry["invalid_parameter_row_count"] += 1
                continue
            key = name.casefold()
            if key in seen_names:
                continue
            seen_names.add(key)
            found_names.append(name)
            if len(found_names) >= MAX_ARJUN_PARAMETERS_PER_URL:
                break
        if len(found_names) >= MAX_ARJUN_PARAMETERS_PER_URL:
            break

    telemetry["discovered_parameter_count"] = len(found_names)
    if not found_names:
        telemetry["parameter_discovery_status"] = (
            "parsed_no_new_parameters" if telemetry["invalid_parameter_row_count"] == 0
            else "parsed_with_invalid_rows"
        )
        telemetry["parameter_artifact_complete"] = telemetry["invalid_parameter_row_count"] == 0
        return [], telemetry

    query = urlencode([*existing_pairs, *((name, "") for name in found_names)])
    parameter_url = urlunsplit((source.scheme, source.netloc, source_path, query, ""))
    try:
        scoped, rejected = filter_in_scope_urls([parameter_url], scope)
    except ValueError:
        scoped, rejected = [], [parameter_url]
    telemetry["out_of_scope_parameter_url_count"] = len(rejected)
    urls = [url for url in scoped if url not in known]
    telemetry["new_parameterized_url_count"] = len(urls)
    telemetry["parameter_artifact_complete"] = telemetry["invalid_parameter_row_count"] == 0
    telemetry["parameter_discovery_status"] = (
        "parsed_with_parameters" if telemetry["parameter_artifact_complete"] else "partial"
    )
    return urls, telemetry


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
    attempted_statuses = {"ok", "nonzero", "timeout", "output_limit", "blocked", "missing", "partial"}
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
    enabled_tools: set[str] | None = None,
    available_tools: set[str] | None = None,
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
        "arjun": [url for url in allowed if not urlparse(url).query],
        "katana": origin_urls,
        "hakrawler": allowed,
        "zap-baseline.py": origin_urls,
        "naabu": origin_urls,
        "dnsx": origin_urls,
        "alterx": origin_urls,
        "nmap": origin_urls,
        "tlsx": [url for url in origin_urls if urlparse(url).scheme.lower() == "https"],
        "sslscan": [url for url in origin_urls if urlparse(url).scheme.lower() == "https"],
        "whatweb": origin_urls,
        "wafw00f": origin_urls,
        "nikto": origin_urls,
        "httpx": origin_urls,
        "subfinder": origin_urls,
        "assetfinder": origin_urls,
        "waybackurls": origin_urls,
        "gau": origin_urls,
    }
    eligible_tools = set(DIRECT_AGENT_TOOLS)
    if browser_xss_profile is not None:
        eligible_tools.add("browser-xss-auth")
    enabled_tools = eligible_tools if enabled_tools is None else set(enabled_tools) & eligible_tools
    available_tools = None if available_tools is None else set(available_tools)
    # Choose one content-discovery engine to avoid duplicate wordlist traffic.
    if available_tools is None:
        dir_tool = "ffuf" if shutil.which("ffuf") else "gobuster"
    else:
        dir_tool = "ffuf" if "ffuf" in available_tools else "gobuster" if "gobuster" in available_tools else None
    arjun_chain_enabled = ("arjun" in enabled_tools and
                           (available_tools is None or "arjun" in available_tools))
    if arjun_chain_enabled:
        candidates_by_tool["dalfox"] = allowed
        candidates_by_tool["browser-xss"] = allowed
        if browser_xss_profile is not None and "browser-xss-auth" in enabled_tools:
            auth_origin = _origin(browser_xss_profile["identity"]["origin"])
            candidates_by_tool["browser-xss-auth"] = [url for url in allowed if _origin(url) == auth_origin]
    if dir_tool in enabled_tools:
        candidates_by_tool[dir_tool] = [
            url for url in origin_urls
            if urlparse(url).path in {"", "/"} and not urlparse(url).query
        ]

    requests = []
    selected_targets = set()
    for tool in (
        "arjun", "browser-xss-auth", "nuclei", "dalfox", "browser-xss", "katana", "hakrawler", "zap-baseline.py",
        "naabu", "dnsx", "alterx", "tlsx", "sslscan", "ffuf", "gobuster",
        "whatweb", "wafw00f", "nikto", "nmap", "httpx",
        "subfinder", "assetfinder", "waybackurls", "gau",
    ):
        if tool not in enabled_tools or (available_tools is not None and tool not in available_tools):
            continue
        if tool not in candidates_by_tool or len(requests) >= MAX_AGENT_REQUESTS:
            continue
        eligible = []
        seen_keys = set()
        for url in candidates_by_tool[tool]:
            key = _coverage_key(tool, url)
            if not key or key in covered[tool] or key in seen_keys:
                continue
            if (tool in {"dalfox", "browser-xss", "browser-xss-auth"} and not urlparse(url).query
                    and not (arjun_chain_enabled and tool in {"dalfox", "browser-xss", "browser-xss-auth"})):
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
    arjun_requested_sources = set()
    for request in requests:
        if str(request.get("tool", "")).strip().lower() != "arjun":
            continue
        raw_targets = request.get("targets", [])
        if isinstance(raw_targets, str):
            raw_targets = [raw_targets]
        if not isinstance(raw_targets, list):
            raw_targets = []
        candidates = [value for value in raw_targets if isinstance(value, str)]
        raw_refs = request.get("target_refs", [])
        if isinstance(raw_refs, str):
            raw_refs = [raw_refs]
        if not isinstance(raw_refs, list):
            raw_refs = []
        candidates.extend((target_references or {}).get(ref) for ref in raw_refs if isinstance(ref, str))
        scoped_sources, _ = filter_in_scope_urls([url for url in candidates if isinstance(url, str)], scope)
        arjun_requested_sources.update(url for url in scoped_sources if url in known)

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
        unsupported_scheme_count = 0
        capacity = (MAX_AGENT_TARGETS if tool in {"httpx", "nuclei", "dalfox"}
                    else MAX_ARJUN_TARGETS if tool == "arjun"
                    else MAX_FOLLOWUP_ORIGINS)
        for url in in_scope:
            if url not in known:
                continue
            parsed = urlparse(url)
            if (tool in {"dalfox", "browser-xss", "browser-xss-auth"} and not parsed.query
                    and url not in arjun_requested_sources):
                continue
            if tool == "browser-xss-auth" and _origin(url) != _origin(browser_xss_profile["identity"]["origin"]):
                continue
            if tool == "tlsx" and parsed.scheme.lower() != "https":
                continue
            if tool == "sslscan" and parsed.scheme.lower() != "https":
                unsupported_scheme_count += 1
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
        if unknown_ref_count or out_scope or unsupported_scheme_count or any(value not in known for value in candidates if value not in out_scope):
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "filtered",
                "out_of_scope_count": len(out_scope),
                "unknown_url_count": sum(1 for value in candidates if value not in known and value not in out_scope),
                "unknown_target_ref_count": unknown_ref_count,
                "unsupported_scheme_count": unsupported_scheme_count,
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
    parameter_urls_by_source = {}
    for index, scan_url in enumerate(selected["arjun"][:MAX_ARJUN_TARGETS], start=1):
        if not shutil.which("arjun"):
            runs.append({"tool": "arjun", "status": "missing", "target": scan_url,
                         "reason": "agent-requested GET parameter discovery; binary not installed"})
            continue
        output = root / f"arjun-get-parameters-{index}.json"
        run = _exec([
            "arjun", "-u", scan_url, "-m", "GET", "-w", "small", "-c", "25",
            "-t", "1", "-T", "10", "-d", "0.5", "--rate-limit", "2",
            "--stable", "--disable-redirects", "-q", "-o", str(output),
        ], timeout=240)
        run["target"] = scan_url
        discovered, telemetry = _arjun_parameter_urls(output, scan_url, scope, known)
        if run.get("status") != "ok":
            telemetry["parameter_discovery_status"] = "process_" + str(run.get("status", "unknown"))
            telemetry["parameter_artifact_complete"] = False
        run.update(telemetry)
        runs.append(run)
        parameter_urls_by_source[scan_url] = discovered
        new_crawl_urls.extend(discovered)

    # Only run validators the planner explicitly selected for a route Arjun
    # actually checked. Newly discovered parameter names stay in exact scope.
    for validator in ("dalfox", "browser-xss", "browser-xss-auth"):
        source_seeds = [url for url in selected[validator]
                        if url in parameter_urls_by_source and not urlparse(url).query]
        seeded = [url for url in selected[validator] if url not in source_seeds]
        for source in source_seeds:
            for candidate in parameter_urls_by_source.get(source, []):
                if validator == "browser-xss-auth" and (
                    browser_xss_profile is None
                    or _origin(candidate) != _origin(browser_xss_profile["identity"]["origin"])
                ):
                    continue
                seeded.append(candidate)
        selected[validator] = list(dict.fromkeys(seeded))

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
    for tool in ("httpx", "katana", "whatweb", "wafw00f", "nikto", "nmap", "tlsx", "sslscan", "dnsx", "naabu", "subfinder", "assetfinder", "waybackurls", "gau", "alterx"):
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
            # A unique output path prevents failed launches/empty timeouts from
            # reusing a previous invocation's probe artifact as fresh evidence.
            output_file = root / f"httpx-followup-responses-{secrets.token_hex(8)}.jsonl"
            result = _exec([tool, "-l", str(target_file), "-json", "-silent", "-rate-limit", "3"],
                           timeout=180, output=output_file)
            probe_urls, probe_telemetry = _http_probe_inventory(output_file, scope, known)
            result.update(probe_telemetry)
            new_crawl_urls.extend(probe_urls)
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
                try:
                    ipaddress.ip_address(hostname)
                except ValueError:
                    runs.append({
                        "tool": tool, "status": "blocked", "target": scan_url,
                        "error_category": "explicit_ip_target_required",
                        "reason": "naabu requires an explicit IP-literal URL; a domain's resolved address is not assumed to be in scope",
                    })
                    continue
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
            elif tool == "sslscan":
                parsed = urlparse(scan_url)
                hostname = parsed.hostname or ""
                if ":" in hostname and not hostname.startswith("["):
                    hostname = f"[{hostname}]"
                command = [tool, "--no-colour", f"{hostname}:{parsed.port or 443}"]
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
        zap_run = run_zap_baseline(scan_url, root, scope, _exec)
        findings.extend(zap_run.pop("findings", []))
        runs.append(zap_run)
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
