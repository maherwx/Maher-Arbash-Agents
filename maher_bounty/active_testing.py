from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse


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
        finding = {
            "source": "nuclei",
            "title": info.get("name") or row.get("template-id") or "Nuclei finding",
            "severity": str(info.get("severity") or "info").lower(),
            "target": row.get("matched-at") or row.get("host") or row.get("url"),
            "template_id": row.get("template-id"),
            "matcher": row.get("matcher-name"),
            "evidence": row.get("extracted-results") or row.get("matcher-status") or row.get("type"),
            "validated": True,
        }
        findings.append(finding)
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
        findings.append({"source":"nikto","title":s.lstrip("+ ")[:180],"severity":"info","target":target,"evidence":s,"validated":False})
    return findings


def _dalfox_findings(path: Path, target: str) -> list[dict]:
    if not path.exists():
        return []
    findings = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        low = line.lower()
        if "vulnerable" in low or "verified" in low:
            findings.append({"source":"dalfox","title":"Potential XSS","severity":"medium","target":target,"evidence":line.strip()[:1000],"validated":"verified" in low})
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


def run_active_testing(target: str, inventory: dict, out_dir: str | Path) -> dict:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.hostname or target
    endpoints = [x.get("value") for x in inventory.get("endpoints", []) if x.get("value")]
    url_list = root / "targets.txt"
    same_host = []
    for url in [target, *endpoints]:
        try:
            if urlparse(url).hostname == host and url not in same_host:
                same_host.append(url)
        except ValueError:
            pass
    url_list.write_text("\n".join(same_host[:1000]) + "\n", encoding="utf-8")

    runs = []
    findings = []

    # Crawl the authorized host to discover application routes and JavaScript-linked paths.
    katana_out = root / "katana.txt"
    runs.append(_exec(["katana", "-u", target, "-silent", "-d", "3", "-jc"], timeout=90, output=katana_out))

    # Template-driven checks produce structured evidence suitable for correlation.
    nuclei_out = root / "nuclei.jsonl"
    runs.append(_exec(["nuclei", "-u", target, "-jsonl", "-severity", "info,low,medium,high,critical", "-o", str(nuclei_out)], timeout=180))
    findings.extend(_nuclei_findings(nuclei_out))

    # Web server/configuration checks.
    nikto_out = root / "nikto.txt"
    runs.append(_exec(["nikto", "-h", target, "-nointeractive"], timeout=120, output=nikto_out))
    findings.extend(_nikto_findings(nikto_out, target))

    # Parameter-aware XSS analysis over discovered in-scope URLs.
    dalfox_out = root / "dalfox.txt"
    if same_host:
        runs.append(_exec(["dalfox", "file", str(url_list), "--silence"], timeout=120, output=dalfox_out))
        findings.extend(_dalfox_findings(dalfox_out, target))

    # Network/TLS/service evidence without destructive NSE scripts.
    nmap_out = root / "nmap.txt"
    runs.append(_exec(["nmap", "-sV", "-Pn", "--top-ports", "100", host], timeout=120, output=nmap_out))
    tlsx_out = root / "tlsx.txt"
    runs.append(_exec(["tlsx", "-u", target, "-silent", "-san", "-cn", "-so"], timeout=60, output=tlsx_out))

    unique = _dedupe(findings)
    summary = {
        "target": target,
        "registered": 6,
        "executed": sum(1 for r in runs if r.get("status") not in ("missing",)),
        "missing": sum(1 for r in runs if r.get("status") == "missing"),
        "timeouts": sum(1 for r in runs if r.get("status") == "timeout"),
        "failed": sum(1 for r in runs if r.get("status") == "nonzero"),
        "raw_findings": len(findings),
        "unique_findings": len(unique),
        "runs": runs,
        "findings": unique,
    }
    (root / "active-testing.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "findings.json").write_text(json.dumps(unique, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[EVIDENCE] raw={len(findings)} unique={len(unique)}", flush=True)
    return summary
