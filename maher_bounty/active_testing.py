from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .scope_policy import filter_in_scope_urls, scope_target_urls


def _exec(cmd: list[str], *, timeout: int, output: Path | None = None) -> dict:
    tool = cmd[0]
    if not shutil.which(tool):
        return {"tool": tool, "status": "missing", "command": cmd, "findings": 0}
    print(f"[ACTIVE] {tool:<12} RUN timeout={timeout}s", flush=True)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        text = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text, encoding="utf-8", errors="ignore")
        status = "ok" if cp.returncode == 0 else "nonzero"
        print(f"[ACTIVE] {tool:<12} {status.upper()}", flush=True)
        return {"tool": tool, "status": status, "returncode": cp.returncode, "command": cmd, "output": str(output) if output else None}
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        if output and partial:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(partial, encoding="utf-8", errors="ignore")
        print(f"[ACTIVE] {tool:<12} TIMEOUT; continuing", flush=True)
        return {"tool": tool, "status": "timeout", "command": cmd, "output": str(output) if output else None}


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
            "source": "nuclei",
            "title": info.get("name") or row.get("template-id") or "Nuclei finding",
            "severity": str(info.get("severity") or "info").lower(),
            "target": row.get("matched-at") or row.get("host") or row.get("url"),
            "template_id": row.get("template-id"),
            "matcher": row.get("matcher-name"),
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
        if not value.startswith("+"):
            continue
        if any(x in value.lower() for x in ("target ip", "target hostname", "target port", "start time", "end time", "server:")):
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


def run_active_testing(target: str | None, inventory: dict, out_dir: str | Path, *, scope: dict | None = None) -> dict:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    inventory = inventory if isinstance(inventory, dict) else {}
    scope = scope if isinstance(scope, dict) else {}
    endpoints = [row.get("value") for row in inventory.get("endpoints", []) if isinstance(row, dict) and row.get("value")]
    assets = scope.get("assets") if isinstance(scope.get("assets"), list) else []
    active_targets, target_rejections = scope_target_urls(scope, inventory, target=target)
    candidates = [*active_targets, *([target] if target else []), *endpoints]
    fallback_target = target if not assets else None
    allowed_urls, rejected_urls = filter_in_scope_urls(candidates, scope, target=fallback_target)
    rejected_urls = list(dict.fromkeys([*rejected_urls, *target_rejections]))
