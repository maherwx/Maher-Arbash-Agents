import argparse
import json
import shutil
import sys
from pathlib import Path

from .orchestrator import run
from .result_store import build_inventory


def doctor():
    tools = [
        "python3", "git", "go", "cargo", "node", "npm",
        "subfinder", "httpx", "dnsx", "naabu", "katana", "nuclei",
        "tlsx", "alterx", "assetfinder", "waybackurls", "gau", "hakrawler",
        "dalfox", "nmap", "ffuf", "gobuster", "whatweb", "wafw00f", "nikto",
    ]
    rows = [{"tool": t, "path": shutil.which(t), "available": bool(shutil.which(t))} for t in tools]
    print(json.dumps({"tools": rows, "available": sum(r["available"] for r in rows), "total": len(rows)}, indent=2))
    return 0 if shutil.which("python3") else 1


def main():
    p = argparse.ArgumentParser(prog="maher-bounty")
    s = p.add_subparsers(dest="cmd", required=True)

    r = s.add_parser("run", help="Run collaborative research agents")
    r.add_argument("--scope", required=True)
    r.add_argument("--rules", required=True)
    r.add_argument("--out", default="reports")
    r.add_argument("--inventory", default=None, help="Normalized inventory.json to feed the research engine")

    inv = s.add_parser("inventory", help="Normalize and deduplicate collected recon data")
    inv.add_argument("result_dir")

    s.add_parser("doctor", help="Check local runtimes and research tools")
    a = p.parse_args()

    if a.cmd == "doctor":
        raise SystemExit(doctor())
    if a.cmd == "inventory":
        data = build_inventory(a.result_dir)
        print(json.dumps(data.get("counts", {}), indent=2))
        print(f"Inventory: {Path(a.result_dir) / 'inventory.json'}")
        return
    if a.cmd == "run":
        result = run(a.scope, a.rules, a.out, a.inventory)
        print(f"Completed {result['agent_count']} agent passes. Reports: {a.out}")


if __name__ == "__main__":
    main()
