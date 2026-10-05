"""Local ZAP CLI execution without an HTTP control API."""
import json
import re
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .scope_policy import is_in_scope_url


def find_zap_executable():
    return next((name for name in ("zap-baseline.py", "zaproxy", "zap.sh") if shutil.which(name)), None)


def run_zap_baseline(target, out_dir, scope, execute):
    parsed = urlparse(target)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or "${" in target or not is_in_scope_url(target, scope)):
        raise ValueError("ZAP target must be a literal in-scope HTTP URL")
    root = Path(out_dir).resolve() / ("zap-" + uuid.uuid4().hex[:12])
    root.mkdir(parents=True, exist_ok=True)
    executable = find_zap_executable()
    if executable == "zap-baseline.py":
        result = execute(["zap-baseline.py", "-t", target, "-m", "2", "-T", "30",
                          "-J", str(root / "report.json"), "-r", str(root / "report.html")], timeout=180)
        return {**result, "tool": "zap-baseline.py", "target": target,
                "execution_engine": "packaged_baseline", "artifact_dir": str(root)}
    if executable is None:
        return {"tool": "zap-baseline.py", "status": "missing", "target": target,
                "reason": "neither packaged baseline nor native ZAP CLI is installed"}
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
    report = root / "report.json"
    if result.get("status") in {"ok", "nonzero"} and result.get("returncode") in {0, 2}:
        try:
            if report.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("oversized report")
            document = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("site"), list):
                raise ValueError("invalid report")
        except (OSError, ValueError):
            result.update(status="nonzero", error_category="zap_report_missing_or_invalid")
        else:
            result["report_path"] = str(report)
            result["report_status"] = "available"
    return result
