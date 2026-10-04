from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .result_store import build_inventory


PASSIVE_TOOLS = ("subfinder","assetfinder","waybackurls","gau","httpx","whatweb","wafw00f")
ACTIVE_DISCOVERY_TOOLS = ("dnsx","katana","tlsx","nmap","naabu","ffuf","gobuster","nikto","nuclei","dalfox","alterx","hakrawler")


def _domain(target: str) -> str:
    raw=target.strip()
    parsed=urlparse(raw if "://" in raw else "https://"+raw)
    host=(parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"invalid target: {target!r}")
    return host


def _run(cmd: list[str], *, stdout_path: Path | None=None, timeout: int=180) -> dict:
    executable=cmd[0]
    if not shutil.which(executable):
        return {"tool":executable,"status":"missing","command":cmd}
    try:
        if stdout_path:
            stdout_path.parent.mkdir(parents=True,exist_ok=True)
            with stdout_path.open("w",encoding="utf-8") as fh:
                cp=subprocess.run(cmd,stdout=fh,stderr=subprocess.PIPE,text=True,timeout=timeout,check=False)
        else:
            cp=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
        return {"tool":executable,"status":"ok" if cp.returncode==0 else "nonzero","returncode":cp.returncode,"stderr":(cp.stderr or "")[-2000:],"command":cmd}
    except subprocess.TimeoutExpired:
        return {"tool":executable,"status":"timeout","command":cmd}


def plan_tools(target: str, rules: dict | None=None) -> dict:
    rules=rules or {}
    allow_active=bool(rules.get("allow_active_discovery",False))
    selected=list(PASSIVE_TOOLS)
    skipped=[]
    if allow_active:
        selected.extend(ACTIVE_DISCOVERY_TOOLS)
    else:
        skipped=[{"tool":t,"reason":"active_discovery_not_enabled"} for t in ACTIVE_DISCOVERY_TOOLS]
    return {"target":target,"domain":_domain(target),"selected":selected,"skipped":skipped,"active_discovery_enabled":allow_active}


def collect_target_inventory(target: str, out_dir: str | Path, *, rules: dict | None=None) -> dict:
    root=Path(out_dir)
    root.mkdir(parents=True,exist_ok=True)
    domain=_domain(target)
    plan=plan_tools(target,rules)
    runs=[]

    runs.append(_run(["subfinder","-silent","-d",domain],stdout_path=root/"subfinder.txt"))
    runs.append(_run(["assetfinder","--subs-only",domain],stdout_path=root/"assetfinder.txt"))
    runs.append(_run(["waybackurls",domain],stdout_path=root/"wayback.txt"))
    runs.append(_run(["gau","--subs",domain],stdout_path=root/"gau.txt"))

    subs=set()
    for p in (root/"subfinder.txt",root/"assetfinder.txt"):
        if p.exists():
            subs.update(x.strip() for x in p.read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip())
    if not subs:
        subs.add(domain)
    (root/"subdomains.txt").write_text("\n".join(sorted(subs))+"\n",encoding="utf-8")

    archives=set()
    for p in (root/"wayback.txt",root/"gau.txt"):
        if p.exists():
            archives.update(x.strip() for x in p.read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip())
    (root/"archive-urls.txt").write_text("\n".join(sorted(archives))+("\n" if archives else ""),encoding="utf-8")

    if shutil.which("httpx"):
        runs.append(_run(["httpx","-silent","-l",str(root/"subdomains.txt"),"-status-code","-title","-tech-detect","-json","-o",str(root/"httpx.jsonl")]))

    metadata=[]
    for tool in ("whatweb","wafw00f"):
        if shutil.which(tool):
            metadata.append(_run([tool,target]))
    plan["runs"]=runs
    plan["metadata_runs"]=metadata

    inventory=build_inventory(root)
    inventory["target"]=target
    inventory["tool_plan"]=plan
    (root/"tool-orchestration.json").write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding="utf-8")
    (root/"inventory.json").write_text(json.dumps(inventory,ensure_ascii=False,indent=2),encoding="utf-8")
    return inventory
