"""Local ZAP CLI execution without an HTTP control API."""
import json
import re
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .burp_evidence import _safe_url
from .scope_policy import is_in_scope_url


def find_zap_executable():
    return next((name for name in ("zap-baseline.py", "zaproxy", "zap.sh") if shutil.which(name)), None)


MAX_ZAP_REPORT_BYTES = 8 * 1024 * 1024
MAX_ZAP_SITES = 100
MAX_ZAP_ALERTS = 2000
MAX_ZAP_FINDINGS = 5000


def _zap_severity(alert):
    try:
        risk = int(alert.get("riskcode"))
    except (TypeError, ValueError):
        risk = None
    return {3: "high", 2: "medium", 1: "low", 0: "informational"}.get(risk, "unspecified")


def _extract_zap_findings(document, report_path, scope):
    sites = document.get("site")
    if not isinstance(sites, list):
        raise ValueError("invalid ZAP report sites")
    findings = []
    alerts_seen = instances_seen = out_of_scope = invalid = 0
    truncated = len(sites) > MAX_ZAP_SITES
    for site in sites[:MAX_ZAP_SITES]:
        if not isinstance(site, dict):
            invalid += 1
            continue
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            invalid += 1
            continue
        if len(alerts) > MAX_ZAP_ALERTS:
            truncated = True
        for alert in alerts[:MAX_ZAP_ALERTS]:
            if not isinstance(alert, dict):
                invalid += 1
                continue
            alerts_seen += 1
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                invalid += 1
                continue
            for instance_index, instance in enumerate(instances, 1):
                if len(findings) >= MAX_ZAP_FINDINGS:
                    truncated = True
                    break
                instances_seen += 1
                if not isinstance(instance, dict):
                    invalid += 1
                    continue
                uri = instance.get("uri") or instance.get("url")
                try:
                    if not isinstance(uri, str) or not is_in_scope_url(uri, scope):
                        out_of_scope += 1
                        continue
                    safe_target = _safe_url(uri)
                except (TypeError, ValueError):
                    invalid += 1
                    continue
                findings.append({
                    "source": "zap-baseline.py",
                    "title": str(alert.get("name") or alert.get("alert") or "ZAP alert")[:300],
                    "target": safe_target,
                    "severity": _zap_severity(alert),
                    "confidence": str(alert.get("confidence") or alert.get("confidenceid") or "")[:100],
                    "evidence": {
                        "kind": "zaproxy_report_instance",
                        "artifact": str(report_path),
                        "instance_index": instance_index,
                        "method": str(instance.get("method") or "")[:20],
                    },
                    "impact": str(alert.get("desc") or "")[:3000],
                    "remediation": str(alert.get("solution") or "")[:2000],
                    "reference": str(alert.get("reference") or "")[:1000],
                    "cwe": str(alert.get("cweid") or "")[:30],
                    "wasc": str(alert.get("wascid") or "")[:30],
                    "validated": False,
                })
            if truncated and len(findings) >= MAX_ZAP_FINDINGS:
                break
        if truncated and len(findings) >= MAX_ZAP_FINDINGS:
            break
    return findings, {
        "status": "partial" if truncated or invalid else "parsed", "alerts_seen": alerts_seen, "instances_seen": instances_seen,
        "findings_extracted": len(findings), "out_of_scope_instances_dropped": out_of_scope,
        "invalid_rows": invalid, "truncated": truncated,
    }


def run_zap_baseline(target, out_dir, scope, execute):
    parsed = urlparse(target)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or "${" in target or not is_in_scope_url(target, scope)):
        raise ValueError("ZAP target must be a literal in-scope HTTP URL")
    root = Path(out_dir).resolve() / ("zap-" + uuid.uuid4().hex[:12])
    root.mkdir(parents=True, exist_ok=True)
    executable = find_zap_executable()
    report = root / "report.json"
    if executable == "zap-baseline.py":
        result = execute(["zap-baseline.py", "-t", target, "-m", "2", "-T", "30",
                          "-J", str(report), "-r", str(root / "report.html")], timeout=180)
        result = {**result, "tool": "zap-baseline.py", "target": target,
                  "execution_engine": "packaged_baseline", "artifact_dir": str(root)}
    elif executable is None:
        return {"tool": "zap-baseline.py", "status": "missing", "target": target,
                "reason": "neither packaged baseline nor native ZAP CLI is installed"}
    else:
        # Exact supplied URL only: this fallback does not crawl or launch active
        # attacks. The native engine passively analyzes the request/response.
        plan = {"env": {"contexts": [{"name": "authorized-target", "urls": [target],
                                      "includePaths": ["^" + re.escape(target) + "$"]}],
                        "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True}},
                "jobs": [{"type": "requestor", "requests": [{"url": target, "method": "GET"}]},
                         {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
                         {"type": "report", "parameters": {"template": "traditional-json",
                                                              "reportDir": str(root), "reportFile": "report",
                                                              "displayReport": False}}]}
        plan_path = root / "automation.yaml"
        plan_path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")
        (root / "profile").mkdir()
        result = execute([executable, "-cmd", "-dir", str(root / "profile"),
                          "-config", "api.disable=true", "-autorun", str(plan_path)], timeout=180)
        result = {**result, "tool": "zap-baseline.py", "target": target, "execution_engine": "native_zap_cli",
                  "artifact_dir": str(root), "plan_path": str(plan_path), "coverage": "exact_url_passive"}

    result["findings"] = []
    if report.is_file():
        try:
            with report.open("rb") as stream:
                raw = stream.read(MAX_ZAP_REPORT_BYTES + 1)
            if len(raw) > MAX_ZAP_REPORT_BYTES:
                raise ValueError("oversized report")
            document = json.loads(raw.decode("utf-8"))
            if not isinstance(document, dict):
                raise ValueError("invalid report root")
            findings, extraction = _extract_zap_findings(document, report, scope)
        except (OSError, UnicodeError, ValueError, RecursionError):
            result.update(error_category="zap_report_missing_or_invalid",
                          finding_extraction={"status": "unavailable", "findings_extracted": 0})
            if result.get("status") == "ok":
                result["status"] = "partial"
        else:
            result.update(report_path=str(report), report_status="available",
                          finding_extraction=extraction, findings=findings)
    else:
        result["finding_extraction"] = {"status": "unavailable", "findings_extracted": 0}
        result["report_status"] = "missing"
        if result.get("status") == "ok":
            result.update(status="partial", error_category="zap_report_missing_or_invalid")
    return result
