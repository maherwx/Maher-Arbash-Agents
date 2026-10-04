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
    exact_assets = []
    for item in assets:
        value = item if isinstance(item, str) else (item.get("url") or item.get("host") or item.get("value") or item.get("asset")) if isinstance(item, dict) else None
        if isinstance(value, str) and value.strip() and not value.strip().startswith("*."):
            exact_assets.append(value.strip())
    candidates = [*exact_assets, *([target] if target else []), *endpoints]
    fallback_target = target if not assets else None
    allowed_urls, rejected_urls = filter_in_scope_urls(candidates, scope, target=fallback_target)
    active_targets, target_rejections = scope_target_urls(scope, inventory, target=target)
    rejected_urls = list(dict.fromkeys([*rejected_urls, *target_rejections]))

    scope_review = {
        "seed_target": target,
        "authorized_targets": active_targets,
        "authorized_url_count": len(allowed_urls),
        "rejected_url_count": len(rejected_urls),
        "allowed_urls": allowed_urls,
        "rejected_urls": rejected_urls,
    }
    (root / "scope-review.json").write_text(json.dumps(scope_review, ensure_ascii=False, indent=2), encoding="utf-8")

    url_list = root / "targets.txt"
    url_list.write_text("\n".join(allowed_urls) + ("\n" if allowed_urls else ""), encoding="utf-8")
    runs = []
    findings = []

    # Run each active tool against every exact asset or discovered host admitted by the program scope.
    for scan_target in active_targets:
        parsed = urlparse(scan_target)
        host = parsed.hostname or ""
        label = re.sub(r"[^A-Za-z0-9._-]", "_", parsed.netloc or host) or "target"
        host_dir = root / "hosts" / label
        host_dir.mkdir(parents=True, exist_ok=True)

        katana_out = host_dir / "katana.txt"
        runs.append(_exec(["katana", "-u", scan_target, "-silent", "-d", "3", "-jc", "-fs", "fqdn"], timeout=90, output=katana_out))

        nuclei_out = host_dir / "nuclei.jsonl"
        runs.append(_exec(["nuclei", "-u", scan_target, "-jsonl", "-severity", "info,low,medium,high,critical", "-o", str(nuclei_out)], timeout=180))
        findings.extend(_nuclei_findings(nuclei_out))

        nikto_out = host_dir / "nikto.txt"
        runs.append(_exec(["nikto", "-h", scan_target, "-nointeractive"], timeout=120, output=nikto_out))
        findings.extend(_nikto_findings(nikto_out, scan_target))

        nmap_out = host_dir / "nmap.txt"
        runs.append(_exec(["nmap", "-sV", "-Pn", "--top-ports", "100", host], timeout=120, output=nmap_out))
        tlsx_out = host_dir / "tlsx.txt"
        runs.append(_exec(["tlsx", "-u", scan_target, "-silent", "-san", "-cn", "-so"], timeout=60, output=tlsx_out))

    if allowed_urls:
        dalfox_out = root / "dalfox.txt"
        runs.append(_exec(["dalfox", "file", str(url_list), "--silence"], timeout=120, output=dalfox_out))
        findings.extend(_dalfox_findings(dalfox_out, target or (active_targets[0] if active_targets else "")))

    unique = _dedupe(findings)
    summary = {
        "seed_target": target,
        "targets": active_targets,
        "target_count": len(active_targets),
        "registered": 5 * len(active_targets) + (1 if allowed_urls else 0),
        "executed": sum(1 for run in runs if run.get("status") != "missing"),
        "missing": sum(1 for run in runs if run.get("status") == "missing"),
        "timeouts": sum(1 for run in runs if run.get("status") == "timeout"),
        "failed": sum(1 for run in runs if run.get("status") == "nonzero"),
        "raw_findings": len(findings),
        "unique_findings": len(unique),
        "scope_review": scope_review,
        "runs": runs,
        "findings": unique,
    }
    (root / "active-testing.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "findings.json").write_text(json.dumps(unique, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[EVIDENCE] targets={len(active_targets)} raw={len(findings)} unique={len(unique)}", flush=True)
    return summary
