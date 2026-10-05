from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .scope_policy import filter_in_scope_urls, scope_target_urls
from .tool_advisor import recommend_tools

SAFE_CONTENT_PATHS = (
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "openapi.json", "swagger.json", "api", "api-docs", "graphql",
    "login", "register", "search", "admin", "health", "status",
)


def _tail(value, limit: int = 3000) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value or "")[-limit:]


def _exec(cmd: list[str], *, timeout: int, output: Path | None = None, input_text: str | None = None) -> dict:
    tool = cmd[0]
    effective_timeout = max(1, int(timeout)) + 180
    if not shutil.which(tool):
        return {"tool": tool, "status": "missing", "command": cmd, "findings": 0, "stderr_tail": ""}
    print(f"[ACTIVE] {tool:<12} RUN timeout={effective_timeout}s (+180s tool allowance)", flush=True)
    try:
        cp = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=effective_timeout, check=False)
        combined = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(combined, encoding="utf-8", errors="ignore")
        status = "ok" if cp.returncode == 0 else "nonzero"
        stderr_tail = _tail(cp.stderr)
        stdout_tail = _tail(cp.stdout, 1000)
        print(f"[ACTIVE] {tool:<12} {status.upper()}", flush=True)
        if status != "ok" and (stderr_tail or stdout_tail):
            diagnostic = (stderr_tail or stdout_tail).replace("\n", " ")[:400]
            print(f"[ACTIVE] {tool:<12} ERROR: {diagnostic}", flush=True)
        return {
            "tool": tool, "status": status, "returncode": cp.returncode, "command": cmd, "timeout_seconds": effective_timeout,
            "output": str(output) if output else None, "stderr_tail": stderr_tail, "stdout_tail": stdout_tail,
        }
    except subprocess.TimeoutExpired as exc:
        partial = _tail(exc.stdout)
        stderr_tail = _tail(exc.stderr)
        if output and (partial or stderr_tail):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(partial + ("\n" + stderr_tail if stderr_tail else ""), encoding="utf-8", errors="ignore")
        print(f"[ACTIVE] {tool:<12} TIMEOUT; continuing", flush=True)
        return {
            "tool": tool, "status": "timeout", "command": cmd, "timeout_seconds": effective_timeout, "output": str(output) if output else None,
            "stderr_tail": stderr_tail, "stdout_tail": partial[-1000:],
        }


def _nuclei_findings(path: Path) -> list[dict]:
    findings = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        findings.append({
            "source": "nuclei", "title": info.get("name") or row.get("template-id") or "Nuclei finding",
            "severity": str(info.get("severity") or "info").lower(),
            "target": row.get("matched-at") or row.get("host") or row.get("url"),
            "template_id": row.get("template-id"), "matcher": row.get("matcher-name"),
            "evidence": row.get("extracted-results") or row.get("matcher-status") or row.get("type"),
            "validated": True,
        })
    return findings


def _nikto_findings(path: Path, target: str) -> list[dict]:
    if not path.exists():
        return []
    findings = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip()
        if not value.startswith("+") or any(x in value.lower() for x in ("target ip", "target hostname", "target port", "start time", "end time", "server:")):
            continue
        findings.append({"source": "nikto", "title": value.lstrip("+ ")[:180], "severity": "info", "target": target, "evidence": value, "validated": False})
    return findings


def _dalfox_findings(path: Path, target: str) -> list[dict]:
    if not path.exists():
        return []
    findings = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        low = line.lower()
        if "vulnerable" in low or "verified" in low:
            findings.append({"source": "dalfox", "title": "Potential XSS", "severity": "medium", "target": target, "evidence": line.strip()[:1000], "validated": "verified" in low})
    return findings


def _dedupe(findings: list[dict]) -> list[dict]:
    merged = {}
    for finding in findings:
        key = (str(finding.get("title", "")).lower(), str(finding.get("target", "")).lower())
        if key not in merged:
            merged[key] = dict(finding, sources=[finding.get("source")])
        else:
            sources = merged[key].setdefault("sources", [])
            if finding.get("source") not in sources:
                sources.append(finding.get("source"))
            merged[key]["validated"] = bool(merged[key].get("validated") or finding.get("validated"))
    return list(merged.values())


def _tool_coverage(inventory: dict, runs: list[dict]) -> list[dict]:
    plan = recommend_tools(inventory, include_active=True)
    statuses = {}
    for row in runs:
        statuses.setdefault(row.get("tool"), []).append(row.get("status"))
    coverage = []
    for recommendation in plan.get("tools", []):
        item = dict(recommendation)
        command = item.get("command")
        if command and command in statuses:
            item["run_statuses"] = statuses[command]
            item["execution_status"] = "skipped" if all(status == "skipped" for status in statuses[command]) else "executed"
        elif item.get("mode") in {"manual_proxy_report_import", "static"}:
            item["execution_status"] = "requires_input"
            item["reason"] = "manual traffic/report or source repository is required"
        elif command and not shutil.which(command):
            item["execution_status"] = "not_installed"
        else:
            item["execution_status"] = "not_scheduled"
            item["reason"] = "not yet wired into the active web workflow"
        coverage.append(item)
    return coverage


def _in_scope_unique(values, scope: dict, *, target: str | None = None) -> list[str]:
    allowed, _ = filter_in_scope_urls(values, scope, target=target)
    return allowed


def _directory_discovery(scan_target: str, host_dir: Path, runs: list[dict], *, preferred_tool: str | None = None) -> list[str]:
    parsed = urlparse(scan_target)
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        runs.append({"tool": "ffuf/gobuster", "status": "skipped", "target": scan_target, "reason": "only origin URLs are eligible for content discovery"})
        return []
    wordlist = host_dir / "safe-content-paths.txt"
    wordlist.write_text("\n".join(SAFE_CONTENT_PATHS) + "\n", encoding="utf-8")
    output_urls = []
    ffuf_ready = bool(shutil.which("ffuf"))
    gobuster_ready = bool(shutil.which("gobuster"))
    if preferred_tool == "ffuf" and not ffuf_ready:
        runs.append({"tool": "ffuf", "status": "missing", "target": scan_target, "reason": "requested directory tool is not installed"})
        return []
    if preferred_tool == "gobuster" and not gobuster_ready:
        runs.append({"tool": "gobuster", "status": "missing", "target": scan_target, "reason": "requested directory tool is not installed"})
        return []
    if preferred_tool == "ffuf" or (preferred_tool is None and ffuf_ready):
        output = host_dir / "ffuf.json"
        runs.append(_exec([
            "ffuf", "-w", str(wordlist), "-u", scan_target.rstrip("/") + "/FUZZ",
            "-rate", "3", "-t", "2", "-maxtime", "30", "-noninteractive",
            "-of", "json", "-o", str(output),
            "-mc", "200,204,301,302,307,401,403",
        ], timeout=45))
        if output.exists():
            try:
                data = json.loads(output.read_text(encoding="utf-8", errors="ignore"))
                output_urls.extend(row.get("url") for row in data.get("results", []) if isinstance(row, dict) and row.get("url"))
            except (OSError, json.JSONDecodeError):
                pass
    elif preferred_tool == "gobuster" or (preferred_tool is None and gobuster_ready):
        output = host_dir / "gobuster.txt"
        runs.append(_exec([
            "gobuster", "dir", "-u", scan_target, "-w", str(wordlist),
            "--threads", "2", "--delay", "300ms", "--timeout", "5s",
            "--no-error", "--quiet", "-o", str(output),
        ], timeout=45))
        if output.exists():
            for line in output.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = re.search(r"Found:\s+(\S+)", line)
                if match:
                    path = match.group(1)
                    output_urls.append(scan_target.rstrip("/") + "/" + path.lstrip("/"))
    else:
        runs.append({"tool": "ffuf/gobuster", "status": "missing", "reason": "neither binary is installed"})
    return output_urls


def run_active_testing(target: str | None, inventory: dict, out_dir: str | Path, *, scope: dict | None = None) -> dict:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    inventory = inventory if isinstance(inventory, dict) else {}
    scope = scope if isinstance(scope, dict) else {}
    endpoints = [row.get("value") for row in inventory.get("endpoints", []) if isinstance(row, dict) and row.get("value")]
    active_targets, target_rejections = scope_target_urls(scope, inventory, target=target)
    target_url = [target] if target and "://" in target else []
    fallback_target = target if not scope.get("assets") else None
    allowed_urls, rejected_urls = filter_in_scope_urls([*active_targets, *target_url, *endpoints], scope, target=fallback_target)
    rejected_urls = list(dict.fromkeys([*rejected_urls, *target_rejections]))
    scope_review = {
        "seed_target": target, "authorized_targets": active_targets,
        "authorized_url_count": len(allowed_urls), "rejected_url_count": len(rejected_urls),
        "allowed_urls": allowed_urls, "rejected_urls": rejected_urls,
    }
    (root / "scope-review.json").write_text(json.dumps(scope_review, ensure_ascii=False, indent=2), encoding="utf-8")
    runs, findings = [], []
    discovered_urls = list(allowed_urls)
    agent_decisions = [{
        "stage": "scope_gate",
        "decision": "admit only exact in-scope HTTP(S) URLs",
        "seed_target": target,
        "allowed_count": len(allowed_urls),
        "rejected_count": len(rejected_urls),
    }]

    seen_origins = set()
    seen_network_hosts = set()
    seen_tls_origins = set()
    for scan_target in active_targets:
        parsed = urlparse(scan_target)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        origin_key = (parsed.scheme.lower(), host, port)
        host_dir_label = (re.sub(r"[^A-Za-z0-9._-]", "_", parsed.netloc or host) or "target") + "-" + hashlib.sha256(scan_target.encode("utf-8")).hexdigest()[:10]
        host_dir = root / "hosts" / host_dir_label
        host_dir.mkdir(parents=True, exist_ok=True)

        if origin_key not in seen_origins:
            seen_origins.add(origin_key)
            before_count = len(discovered_urls)
            katana_out = host_dir / "katana.txt"
            crawl_run = _exec(["katana", "-u", scan_target, "-silent", "-d", "3", "-jc", "-fs", "fqdn"], timeout=90, output=katana_out)
            runs.append(crawl_run)
            if katana_out.exists():
                crawled = [line.strip() for line in katana_out.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
                discovered_urls.extend(_in_scope_unique(crawled, scope, target=fallback_target))
            directory_urls = _directory_discovery(scan_target, host_dir, runs)
            discovered_urls.extend(_in_scope_unique(directory_urls, scope, target=fallback_target))
            agent_decisions.append({
                "stage": "web_discovery",
                "target": scan_target,
                "tools": ["katana", "ffuf" if shutil.which("ffuf") else "gobuster"],
                "crawl_status": crawl_run.get("status"),
                "new_in_scope_urls": max(0, len(discovered_urls) - before_count),
                "next": "classify discovered routes and choose validators",
            })
            nikto_out = host_dir / "nikto.txt"
            runs.append(_exec(["nikto", "-h", scan_target, "-nointeractive"], timeout=120, output=nikto_out))
            if shutil.which("zap-baseline.py"):
                runs.append(_exec([
                    "zap-baseline.py", "-t", scan_target, "-m", "2", "-T", "30",
                    "-J", str(host_dir / "zap-baseline.json"), "-r", str(host_dir / "zap-baseline.html"),
                ], timeout=180))
        else:
            for tool in ("katana", "ffuf/gobuster", "nikto", "zap-baseline.py"):
                runs.append({
                    "tool": tool, "status": "skipped", "target": scan_target,
                    "reason": "already executed for this origin in the current run",
                })
            agent_decisions.append({
                "stage": "deduplication", "target": scan_target,
                "decision": "reuse existing origin coverage",
                "reason": "the same scheme, host, and port were already tested in this run",
            })

        if host not in seen_network_hosts:
            seen_network_hosts.add(host)
            runs.append(_exec(
                ["nmap", "-sV", "-Pn", "--top-ports", "100", host],
                timeout=120, output=host_dir / "nmap.txt",
            ))
        else:
            runs.append({
                "tool": "nmap", "status": "skipped", "target": scan_target,
                "reason": "network host already tested in this run",
            })

        if parsed.scheme.lower() == "https" and origin_key not in seen_tls_origins:
            seen_tls_origins.add(origin_key)
            runs.append(_exec(
                ["tlsx", "-u", scan_target, "-silent", "-san", "-cn"],
                timeout=60, output=host_dir / "tlsx.txt",
            ))
        elif parsed.scheme.lower() != "https":
            runs.append({
                "tool": "tlsx", "status": "skipped", "target": scan_target,
                "reason": "TLS certificate probing applies to HTTPS targets",
            })
        else:
            runs.append({
                "tool": "tlsx", "status": "skipped", "target": scan_target,
                "reason": "TLS host and port already probed in this run",
            })

    discovered_urls = _in_scope_unique(discovered_urls, scope, target=fallback_target)
    target_file = root / "targets.txt"
    target_file.write_text("\n".join(discovered_urls) + ("\n" if discovered_urls else ""), encoding="utf-8")
    parsed_routes = [urlparse(value) for value in discovered_urls]
    parameter_urls = [value for value in discovered_urls if urlparse(value).query]
    javascript_urls = [value for value in discovered_urls if urlparse(value).path.lower().endswith((".js", ".mjs"))]
    api_urls = [value for value in discovered_urls if any(token in urlparse(value).path.lower() for token in ("/api", "graphql", "openapi", "swagger")) or urlparse(value).path.lower().endswith(".json")]
    route_types = {
        "urls": len(discovered_urls),
        "parameterized": len(parameter_urls),
        "javascript": len(javascript_urls),
        "api_like": len(api_urls),
    }
    if discovered_urls:
        agent_decisions.append({
            "stage": "route_analysis",
            "decision": "run Nuclei across all admitted URLs",
            "reason": "scope-filtered inventory and crawler results are available",
            "route_types": route_types,
        })
        nuclei_out = root / "nuclei.jsonl"
        runs.append(_exec([
            "nuclei", "-l", str(target_file), "-jsonl", "-severity", "info,low,medium,high,critical",
            "-rate-limit", "5", "-concurrency", "5", "-timeout", "10", "-retries", "1",
            "-o", str(nuclei_out),
        ], timeout=240))
        findings.extend(_nuclei_findings(nuclei_out))
        if parameter_urls or javascript_urls:
            dalfox_out = root / "dalfox.txt"
            dalfox_file = root / "dalfox-targets.txt"
            dalfox_targets = list(dict.fromkeys([*parameter_urls, *javascript_urls]))
            dalfox_file.write_text("\n".join(dalfox_targets) + "\n", encoding="utf-8")
            agent_decisions.append({
                "stage": "xss_triage",
                "decision": "run Dalfox on parameterized and JavaScript URLs",
                "reason": "route classifier found XSS-relevant inputs",
                "url_count": len(dalfox_targets),
            })
            runs.append(_exec(["dalfox", "file", str(dalfox_file), "--silence"], timeout=180, output=dalfox_out))
            findings.extend(_dalfox_findings(dalfox_out, target or dalfox_targets[0]))
        else:
            agent_decisions.append({
                "stage": "xss_triage",
                "decision": "skip Dalfox",
                "reason": "no parameterized or JavaScript URLs were discovered",
            })
            runs.append({"tool": "dalfox", "status": "skipped", "reason": "no parameterized or JavaScript URLs were discovered"})
    else:
        agent_decisions.append({
            "stage": "route_analysis",
            "decision": "skip URL validators",
            "reason": "no in-scope URLs survived scope filtering",
        })

    unique = _dedupe(findings)
    adaptive_tool_plan = recommend_tools(inventory, include_active=True)
    summary = {
        "adaptive_coordinator": {"name": "scope-aware-tool-coordinator", "mode": "deterministic_evidence_driven", "decisions": agent_decisions},
        "route_types": route_types if discovered_urls else {"urls": 0, "parameterized": 0, "javascript": 0, "api_like": 0},
        "seed_target": target, "targets": active_targets, "target_count": len(active_targets),
        "discovered_in_scope_url_count": len(discovered_urls), "discovered_in_scope_urls": discovered_urls,
        "rejected_url_count": len(rejected_urls), "registered": len(runs),
        "executed": sum(1 for row in runs if row.get("status") not in {"missing", "skipped"}),
        "missing": sum(1 for row in runs if row.get("status") == "missing"),
        "timeouts": sum(1 for row in runs if row.get("status") == "timeout"),
        "failed": sum(1 for row in runs if row.get("status") == "nonzero"),
        "raw_findings": len(findings), "unique_findings": len(unique),
        "scope_review": scope_review, "adaptive_tool_plan": adaptive_tool_plan,
        "tool_coverage": _tool_coverage(inventory, runs), "runs": runs, "findings": unique,
    }
    (root / "active-testing.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "findings.json").write_text(json.dumps(unique, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[EVIDENCE] targets={len(active_targets)} urls={len(discovered_urls)} raw={len(findings)} unique={len(unique)}", flush=True)
    return summary
