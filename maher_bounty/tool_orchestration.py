from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .result_store import build_inventory, stable_id
from .scope_policy import is_in_scope_url


PASSIVE_TOOLS = ("subfinder", "assetfinder", "waybackurls", "gau", "httpx", "whatweb", "wafw00f")
ACTIVE_DISCOVERY_TOOLS = ("dnsx", "katana", "tlsx", "nmap", "naabu", "ffuf", "gobuster", "nikto", "nuclei", "dalfox", "alterx", "hakrawler")
PASSIVE_TIMEOUTS = {
    "subfinder": 90,
    "assetfinder": 45,
    "waybackurls": 60,
    "gau": 90,
    "httpx": 60,
    "whatweb": 45,
    "wafw00f": 45,
}


def _domain(target: str) -> str:
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"invalid target: {target!r}")
    return host


def _normalized_url(target: str) -> str:
    raw = target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname or parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"invalid HTTP(S) target: {target!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URLs must not embed credentials")
    return raw


def _run(cmd: list[str], *, stdout_path: Path | None = None, timeout: int = 30) -> dict:
    executable = cmd[0]
    effective_timeout = max(1, int(timeout)) + 180
    if not shutil.which(executable):
        return {"tool": executable, "status": "missing", "command": cmd}
    print(f"[tool] {executable} started (timeout={effective_timeout}s; base={timeout}s + 180s)", flush=True)
    try:
        if stdout_path:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            with stdout_path.open("w", encoding="utf-8") as fh:
                cp = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True, timeout=effective_timeout, check=False)
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        status = "ok" if cp.returncode == 0 else "nonzero"
        print(f"[tool] {executable} {status}", flush=True)
        return {"tool": executable, "status": status, "returncode": cp.returncode, "stderr": (cp.stderr or "")[-2000:], "command": cmd, "timeout_seconds": effective_timeout}
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        print(f"[tool] {executable} timed out; continuing", flush=True)
        return {"tool": executable, "status": "timeout", "command": cmd, "timeout_seconds": effective_timeout, "stderr": str(stderr)[-2000:]}


def plan_tools(target: str, rules: dict | None = None) -> dict:
    rules = rules or {}
    allow_active = bool(rules.get("allow_active_discovery", False))
    selected = list(PASSIVE_TOOLS)
    skipped = []
    if allow_active:
        selected.extend(ACTIVE_DISCOVERY_TOOLS)
    else:
        skipped = [{"tool": t, "reason": "active_discovery_not_enabled"} for t in ACTIVE_DISCOVERY_TOOLS]
    return {"target": target, "domain": _domain(target), "selected": selected, "skipped": skipped, "active_discovery_enabled": allow_active}


def collect_target_inventory(target: str, out_dir: str | Path, *, rules: dict | None = None, scope: dict | None = None) -> dict:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    target_url = _normalized_url(target)
    domain = _domain(target)
    plan = plan_tools(target_url, rules)
    runs = []

    print(f"[1/5] Target accepted: {target_url}", flush=True)
    print("[2/5] Collecting passive reconnaissance", flush=True)
    passive_jobs = [
        (["subfinder", "-silent", "-d", domain], root / "subfinder.txt"),
        (["assetfinder", "--subs-only", domain], root / "assetfinder.txt"),
        (["waybackurls", domain], root / "wayback.txt"),
        (["gau", "--subs", domain], root / "gau.txt"),
    ]
    for cmd, output in passive_jobs:
        runs.append(_run(cmd, stdout_path=output, timeout=PASSIVE_TIMEOUTS[cmd[0]]))

    subs = {domain}
    for path in (root / "subfinder.txt", root / "assetfinder.txt"):
        if path.exists():
            subs.update(x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip())

    # HTTP probing is directed only at hosts included by the program's asset rules.
    if scope:
        fallback = target if not scope.get("assets") else None
        allowed_subs = sorted(x for x in subs if is_in_scope_url("https://" + x, scope, target=fallback))
        plan["out_of_scope_hosts_filtered"] = len(subs) - len(allowed_subs)
    else:
        allowed_subs = sorted(subs)
    (root / "subdomains.txt").write_text("\n".join(allowed_subs) + ("\n" if allowed_subs else ""), encoding="utf-8")

    archives = {target_url}
    for path in (root / "wayback.txt", root / "gau.txt"):
        if path.exists():
            archives.update(x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip())
    (root / "archive-urls.txt").write_text("\n".join(sorted(archives)) + "\n", encoding="utf-8")

    print("[3/5] Probing discovered in-scope web targets", flush=True)
    if allowed_subs and shutil.which("httpx"):
        runs.append(_run(
            ["httpx", "-silent", "-l", str(root / "subdomains.txt"), "-status-code", "-title", "-tech-detect", "-json", "-o", str(root / "httpx.jsonl")],
            timeout=PASSIVE_TIMEOUTS["httpx"],
        ))

    metadata = []
    for tool in ("whatweb", "wafw00f"):
        if shutil.which(tool) and is_in_scope_url(target_url, scope, target=target if not scope else None):
            metadata.append(_run([tool, target_url], timeout=PASSIVE_TIMEOUTS[tool]))
    plan["runs"] = runs
    plan["metadata_runs"] = metadata

    print("[4/5] Building normalized inventory", flush=True)
    inventory = build_inventory(root)

    if is_in_scope_url(target_url, scope, target=target if not scope else None):
        if not any(x.get("value") == target_url for x in inventory.get("endpoints", [])):
            inventory.setdefault("endpoints", []).insert(0, {"id": stable_id("url", target_url), "value": target_url})
    inventory.setdefault("counts", {})["endpoints"] = len(inventory.get("endpoints", []))
    inventory["target"] = target_url
    inventory["tool_plan"] = plan

    (root / "tool-orchestration.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[5/5] Inventory ready: {inventory.get('counts', {})}", flush=True)
    return inventory
