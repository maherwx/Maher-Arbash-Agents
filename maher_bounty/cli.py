import argparse
import json
import shutil
from pathlib import Path

from .orchestrator import run
from .result_store import build_inventory
from .traffic_ingest import ingest_traffic
from .traffic_pipeline import analyze_traffic
from .continuous_service import ContinuousAnalysisService, ServiceConfig, write_status


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


def _service_config(args):
    return ServiceConfig(
        watch_dir=args.watch,
        output_dir=args.out,
        db_path=args.service_db,
        research_db_path=args.research_db,
        poll_seconds=args.poll,
        worker_count=args.workers,
        retry_limit=args.retries,
        retry_backoff_seconds=args.backoff,
    )


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

    traffic = s.add_parser("traffic-import", help="Import Burp XML or HAR/ZAP traffic")
    traffic.add_argument("path")
    traffic.add_argument("--kind", choices=["auto", "burp", "har", "zap"], default="auto")
    traffic.add_argument("--out", default="results/traffic.json")

    ta = s.add_parser("traffic-analyze", help="Run canonicalization, behavioral modeling and anomaly clustering")
    ta.add_argument("path")
    ta.add_argument("--kind", choices=["auto", "burp", "har", "zap"], default="auto")
    ta.add_argument("--out", default="results/traffic-analysis")
    ta.add_argument("--db", default=".maher/research.db")

    svc = s.add_parser("serve", help="Run continuous incremental analysis service")
    svc.add_argument("--watch", default="incoming")
    svc.add_argument("--out", default="results/continuous")
    svc.add_argument("--service-db", default=".maher/service.db")
    svc.add_argument("--research-db", default=".maher/research.db")
    svc.add_argument("--poll", type=float, default=2.0)
    svc.add_argument("--workers", type=int, default=2)
    svc.add_argument("--retries", type=int, default=3)
    svc.add_argument("--backoff", type=float, default=5.0)

    status = s.add_parser("service-status", help="Show continuous service job state")
    status.add_argument("--watch", default="incoming")
    status.add_argument("--out", default="results/continuous")
    status.add_argument("--service-db", default=".maher/service.db")
    status.add_argument("--research-db", default=".maher/research.db")
    status.add_argument("--poll", type=float, default=2.0)
    status.add_argument("--workers", type=int, default=2)
    status.add_argument("--retries", type=int, default=3)
    status.add_argument("--backoff", type=float, default=5.0)

    s.add_parser("doctor", help="Check local runtimes and research tools")
    a = p.parse_args()

    if a.cmd == "doctor":
        raise SystemExit(doctor())
    if a.cmd == "inventory":
        data = build_inventory(a.result_dir)
        print(json.dumps(data.get("counts", {}), indent=2))
        print(f"Inventory: {Path(a.result_dir) / 'inventory.json'}")
        return
    if a.cmd == "traffic-import":
        records = ingest_traffic(a.path, a.kind)
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"records": records, "count": len(records)}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Imported {len(records)} traffic records: {out}")
        return
    if a.cmd == "traffic-analyze":
        result = analyze_traffic(a.path, kind=a.kind, out_dir=a.out, db_path=a.db)
        print(json.dumps({
            "run_id": result["run_id"],
            "record_count": result["record_count"],
            "route_families": result["behavior"]["route_family_count"],
            "anomalies": result["anomalies"]["anomaly_count"],
            "out": a.out,
        }, indent=2))
        return
    if a.cmd == "serve":
        service = ContinuousAnalysisService(_service_config(a))
        try:
            print(json.dumps({"status": "starting", **service.status()}, indent=2))
            service.run_forever()
        finally:
            service.close()
        return
    if a.cmd == "service-status":
        print(json.dumps(write_status(_service_config(a)), indent=2))
        return
    if a.cmd == "run":
        result = run(a.scope, a.rules, a.out, a.inventory)
        print(f"Completed {result['agent_count']} agent passes. Reports: {a.out}")


if __name__ == "__main__":
    main()
