import argparse
import json
from pathlib import Path

from .orchestrator import run, run_target
from .result_store import build_inventory
from .traffic_ingest import ingest_traffic
from .traffic_pipeline import analyze_traffic
from .continuous_service import ContinuousAnalysisService, ServiceConfig, write_status
from .tool_registry import tool_status
from .model_adapter import LocalModelAdapter
from .run_history import RunHistory
from .benchmark import run_benchmark


def doctor():
    status = tool_status()
    print(json.dumps(status, indent=2))
    return 1 if status["required_missing"] else 0


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

    auto = s.add_parser("auto-run", help="Collect target inventory and run the full collaborative pipeline")
    auto.add_argument("--target", required=True, help="Authorized website/domain target")
    auto.add_argument("--authorized", action="store_true", help="Confirm you own or have explicit permission to test this target")
    auto.add_argument("--rules", default=None, help="Optional rules YAML; safe defaults are used when omitted")
    auto.add_argument("--out", default="results/auto")

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

    model = s.add_parser("model-status", help="Show configured local model failover pool")
    model.add_argument("--json", action="store_true")

    hist = s.add_parser("history", help="List recent research runs")
    hist.add_argument("--db", default=".maher/research.db")
    hist.add_argument("--limit", type=int, default=20)

    show = s.add_parser("run-show", help="Show one persisted research run")
    show.add_argument("run_id", type=int)
    show.add_argument("--db", default=".maher/research.db")

    export = s.add_parser("run-export", help="Export one persisted research run to JSON")
    export.add_argument("run_id", type=int)
    export.add_argument("--db", default=".maher/research.db")
    export.add_argument("--out", required=True)

    bench = s.add_parser("benchmark", help="Run the deterministic quality benchmark corpus")
    bench.add_argument("--out", default="results/benchmark")
    bench.add_argument("--require-pass", action="store_true")

    s.add_parser("doctor", help="Check local runtimes and research tools")
    a = p.parse_args()

    if a.cmd == "doctor":
        raise SystemExit(doctor())

    if a.cmd == "model-status":
        payload = LocalModelAdapter().status()
        print(json.dumps(payload, indent=2))
        return

    if a.cmd == "history":
        print(json.dumps(RunHistory(a.db).list_runs(a.limit), ensure_ascii=False, indent=2))
        return

    if a.cmd == "run-show":
        print(json.dumps(RunHistory(a.db).load_run(a.run_id), ensure_ascii=False, indent=2))
        return

    if a.cmd == "run-export":
        path = RunHistory(a.db).export_run(a.run_id, a.out)
        print(str(path))
        return

    if a.cmd == "benchmark":
        result = run_benchmark(a.out)
        print(json.dumps({
            "case_count": result.get("case_count"),
            "passed": result.get("passed"),
            "failed": result.get("failed"),
            "pass_rate": result.get("pass_rate"),
            "quality": result.get("quality", {}),
            "quality_gate": result.get("quality_gate", {}),
            "out": a.out,
        }, indent=2))
        if a.require_pass and (result.get("failed") or not result.get("quality_gate", {}).get("passed")):
            raise SystemExit(2)
        return

    if a.cmd == "inventory":
        data = build_inventory(a.result_dir)
        print(json.dumps(data.get("counts", {}), indent=2))
        print(f"Inventory: {Path(a.result_dir) / 'inventory.json'}")
        return

    if a.cmd == "traffic-import":
        records = ingest_traffic(a.path, a.kind)
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps({"records": records, "count": len(records)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
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
        return

    if a.cmd == "auto-run":
        result = run_target(a.target, a.rules, a.out, authorized=a.authorized)
        print(json.dumps({
            "target": a.target,
            "inventory_counts": result.get("inventory_counts", {}),
            "agent_count": result.get("agent_count", 0),
            "routed_agents": result.get("agent_routing", {}).get("selected_count", 0),
            "active_discovery_enabled": result.get("tool_plan", {}).get("active_discovery_enabled", False),
            "model_status": result.get("model_status", {}),
            "out": a.out,
        }, indent=2))
        return


if __name__ == "__main__":
    main()
