from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _run(cmd, cwd=None, timeout=180):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        if p.returncode != 0:
            return {"status": "error", "command": cmd[0], "error": (p.stderr or p.stdout)[-2000:]}
        return {"status": "ok", "data": json.loads(p.stdout)}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"status": "error", "command": cmd[0], "error": str(exc)}


def run_native_engines(inventory_path: str | Path) -> dict:
    """Run optional high-performance local engines when their runtimes exist."""
    root = Path(__file__).resolve().parent.parent
    inv = str(Path(inventory_path).resolve())
    output = {}

    if shutil.which("cargo"):
        output["rust"] = _run(["cargo", "run", "--quiet", "--release", "--", inv], cwd=root / "engine" / "rust-core", timeout=300)
    else:
        output["rust"] = {"status": "unavailable", "reason": "cargo not installed"}

    if shutil.which("go"):
        output["go"] = _run(["go", "run", ".", inv], cwd=root / "engine" / "go-core", timeout=180)
    else:
        output["go"] = {"status": "unavailable", "reason": "go not installed"}

    return output
