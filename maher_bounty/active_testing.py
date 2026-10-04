from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .scope_policy import filter_in_scope_urls


def _exec(cmd: list[str], *, timeout: int, output: Path | None = None) -> dict:
    tool = cmd[0]
    path = shutil.which(tool)
    if not path:
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
        s = line.strip()
        if not s.startswith("+"):
            continue
        if any(x in s.lower() for x in ("target ip", "target hostname", "target port", "start time", "end time", "server:")):
            continue
        findings.append({"source": "nikto", "title": s.lstrip("+ ")[:180], "severity": "info", "target": target, "evidence": s, "validated": False})
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
    for f in findings:
        key = (str(f.get("title", "")).lower(), str(f.get("target", "")).lower())
        if key not in merged:
            merged[key] = dict(f, sources=[f.get("source")])
        else:
            sources = merged[key].setdefault("sources", [])
            if f.get("source") not in sources:
                sources.append(f.get("source"))
            merged[key]["validated"] = bool(merged[key].get("validated") or f.get("validated"))
    return list(merged.values())


def run_active_testing(target: str, inventory: dict, out_dir: str | Path, *, scope: dict | None = None) -> dict:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.hostname or target
    endpoints = [x.get("value") for x in inventory.get("endpoints", []) if isinstance(x, dict) and x.get("value")]
    in_scope, rejected = filter_in_scope_urls([target, *endpoints], scope, target=target)
    normalized_target = next((url for url in in_scope if urlparse(url if "://" in url else "https://" + url).hostname == host), None)
    if normalized_target is None:
        raise ValueError("active testing target is not permitted by the supplied scope")

    # Persist the scope decision so every discarded endpoint is auditable.
    scope_review = {
        "target": target,
        "allowed_url_count": min(len(in_scope), 1000),
        "rejected_url_count": len(rejected),
        "allowed_urls": in_scope[:1000],
        "rejected_urls": rejected[:1000],
    }
    (root / "scope-review.json").write_text(json.dumps(scope_review, ensure_ascii=False, indent=2), encoding="utf-8")

    url_list = root / "targets.txt"
    url_list.write_text("\n".join(in_scope[:1000]) + "\n", encoding="utf-8")

    runs = []
    findings = []

    # Crawl only the explicitly authorized starting host.
    katana_out = root / "katana.txt"
    runs.append(_exec(["katana", "-u", normalized_target, "-silent", "-d", "3", "-jc"], timeout=90, output=katana_out))

    # Template-driven checks produce structured evidence suitable for correlation.
    nuclei_out = root / "nuclei.jsonl"
    runs.append(_exec(["nuclei", "-u", normalized_target, "-jsonl", "-severity", "info,low,medium,high,critical", "-o", str(nuclei_out)], timeout=180))
    findings.extend(_nuclei_findings(nuclei_out))

    # Web server/configuration checks.
    nikto_out = root / "nikto.txt"
    runs.append(_exec(["nikto", "-h", normalized_target, "-nointeractive"], timeout=120, output=nikto_out))
    findings.extend(_nikto_findings(nikto_out, normalized_target))

    # Parameter-aware XSS analysis over explicitly in-scope URLs only.
    dalfox_out = root / "dalfox.txt"
    if in_scope:
        runs.append(_exec(["dalfox", "file", str(url_list), "--silence"], timeout=120, output=dalfox_out))
        findings.extend(_dalfox_findings(dalfox_out, normalized_target))

    # Network/TLS/service evidence without destructive NSE scripts.
    nmap_out = root / "nmap.txt"
    runs.append(_exec(["nmap", "-sV", "-Pn", "--top-ports", "100", host], timeout=120, output=nmap_out))
    tlsx_out = root / "tlsx.txt"
    runs.append(_exec(["tlsx", "-u", normalized_target, "-silent", "-san", "-cn", "-so"], timeout=60, output=tlsx_out))

    unique = _dedupe(findings)
    summary = {
        "target": target,
        "registered": 6,
        "executed": sum(1 for r in runs if r.get("status") != "missing"),
        "missing": sum(1 for r in runs if r.get("status") == "missing"),
        "timeouts": sum(1 for r in runs if r.get("status") == "timeout"),
        "failed": sum(1 for r in runs if r.get("status") == "nonzero"),
        "raw_findings": len(findings),
        "unique_findings": len(unique),
        "scope_review": scope_review,
        "runs": runs,
        "findings": unique,
    }
    (root / "active-testing.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "findings.json").write_text(json.dumps(unique, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[EVIDENCE] raw={len(findings)} unique={len(unique)}", flush=True)
    return summary
