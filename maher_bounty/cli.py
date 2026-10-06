import argparse
import json
import shutil
import sys
from pathlib import Path

from .orchestrator import run, run_target
from .result_store import build_inventory
from .traffic_ingest import ingest_traffic, TrafficInputError
from .traffic_pipeline import analyze_traffic
from .workflow_execution import execute_workflows
from .continuous_service import ContinuousAnalysisService, ServiceConfig, write_status
from .source_review import review_source
from .api_contract import review_api_contract, ContractInputError
from .policy_agents import run_policy_agents
from .agent_terminal import run_agent_terminal, load_execution_json, AgentExecutionInputError


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
    try:
        return _main()
    except (TrafficInputError, ContractInputError, AgentExecutionInputError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _main():
    p = argparse.ArgumentParser(prog="maher-bounty")
    s = p.add_subparsers(dest="cmd", required=True)

    r = s.add_parser("run", help="Run collaborative research agents")
    r.add_argument("--scope", required=True)
    r.add_argument("--rules", required=True)
    r.add_argument("--out", default="reports")
    r.add_argument("--inventory", default=None, help="Normalized inventory.json to feed the research engine")
    r.add_argument("--traffic", default=None, help="Burp XML or HAR export to scope-filter and share with agents")
    r.add_argument("--authorized", action="store_true", help="Confirm permission for active checks against the supplied scope")
    r.add_argument("--workflow-manifest", default=None, help="JSON manifest of test identities, access policies and workflow invariants")
    r.add_argument("--source-dir", default=None, help="Local application source directory for multilingual static review")
    r.add_argument("--api-contract", default=None, help="Local OpenAPI 3 JSON contract for bounded API policy review")

    auto = s.add_parser("auto-run", help="Collect target inventory and run the full collaborative pipeline")
    auto.add_argument("--target", required=True, help="Authorized website/domain target")
    auto.add_argument("--authorized", action="store_true", help="Confirm you own or have explicit permission to test this target")
    auto.add_argument("--rules", default=None, help="Optional rules YAML; safe defaults are used when omitted")
    auto.add_argument("--out", default="results/auto")
    auto.add_argument("--traffic", default=None, help="Burp XML or HAR export to scope-filter and share with agents")
    auto.add_argument("--workflow-manifest", default=None, help="Execute authenticated access policies and workflow invariants")
    auto.add_argument("--source-dir", default=None, help="Local application source directory for multilingual static review")
    auto.add_argument("--api-contract", default=None, help="Local OpenAPI 3 JSON contract")

    contract = s.add_parser("api-contract-review", help="Review local OpenAPI operations and declared authorization without network requests")
    contract.add_argument("path", help="Local OpenAPI 3.0/3.1 JSON")
    contract.add_argument("--out", default="results/api-contract")

    source = s.add_parser("source-review", help="Review multilingual local source using native checks and optional local Semgrep CE")
    source.add_argument("--source-dir", required=True)
    source.add_argument("--out", default="results/source-review")

    wf = s.add_parser("workflow-run", help="Execute application-specific access policies and workflow invariants")
    wf.add_argument("manifest", help="JSON assessment manifest")
    wf.add_argument("--scope", required=True, help="JSON scope with assets and out_of_scope")
    wf.add_argument("--authorized", action="store_true")
    wf.add_argument("--out", default="results/workflows")

    policy = s.add_parser("policy-agents-run", help="Execute declared policy tests using native planning, execution and evidence-review agents")
    policy.add_argument("manifest", help="JSON identities and authorized access/state/workflow cases")
    policy.add_argument("--scope", required=True)
    policy.add_argument("--authorized", action="store_true")
    policy.add_argument("--out", default="results/policy-agents")

    terminal = s.add_parser("agent-tools-run", help="Plan, execute and review scoped local tools directly without recon setup")
    terminal.add_argument("--targets", required=True, help="Local JSON array of exact authorized URLs")
    terminal.add_argument("--scope", required=True)
    terminal.add_argument("--requests", help="Optional local JSON worker tool-request packets")
    terminal.add_argument("--authorized", action="store_true")
    terminal.add_argument("--local-model", action="store_true", help="Require configured in-process GGUF reasoning")
    terminal.add_argument("--plan-only", action="store_true", help="Write plan without launching target tools")
    terminal.add_argument("--rounds", type=int, choices=[1, 2, 3], default=3)
    terminal.add_argument("--out", default="results/agent-tools")

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
    bench = s.add_parser("workflow-benchmark", help="Evaluate access/state detection against generated local fixtures")
    bench.add_argument("--engine", choices=["http", "browser"], default="http")
    bench.add_argument("--out", default="results/workflow-benchmark")
    a = p.parse_args()
    if a.cmd == "agent-tools-run":
        result = run_agent_terminal(load_execution_json(a.targets), load_execution_json(a.scope), a.out,
            authorized=a.authorized, requests=load_execution_json(a.requests) if a.requests else None,
            local_model=a.local_model, plan_only=a.plan_only, max_rounds=a.rounds)
        print(json.dumps({"status": result["status"], "run_status_counts": result.get("run_status_counts", {}),
                          "finding_report": result.get("finding_report"),
                          "out": a.out}, indent=2))
        return 0
    if a.cmd == "policy-agents-run":
        result = run_policy_agents(json.loads(Path(a.manifest).read_text(encoding="utf-8")),
                                   json.loads(Path(a.scope).read_text(encoding="utf-8")), a.out,
                                   authorized=a.authorized)
        execution = result["execution"]
        print(json.dumps({"status": execution["status"], "requests": execution["requests"],
                          "selected_cases": result["selected_case_count"], "out": a.out}, indent=2))
        return
    if a.cmd == "api-contract-review":
        result = review_api_contract(a.path, a.out)
        print(json.dumps({"status": result["status"], "operations": result["operation_count"],
                          "coverage_gaps": result["coverage_gaps"], "out": a.out}, indent=2))
        return

    if a.cmd == "workflow-benchmark":
        from .workflow_benchmark import run_workflow_benchmark
        result = run_workflow_benchmark(a.out, engine=a.engine)
        print(json.dumps(result, indent=2))
        return 0 if result["quality_gate_passed"] else 1

    if a.cmd == "workflow-run":
        result = execute_workflows(json.loads(Path(a.manifest).read_text(encoding="utf-8")),
                                   json.loads(Path(a.scope).read_text(encoding="utf-8")),
                                   a.out, authorized=a.authorized)
        print(json.dumps({"status": result["status"], "requests": result["requests"],
                          "findings": len(result["findings"]), "out": a.out}, indent=2))
        return

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
        result = run(
            a.scope, a.rules, a.out, a.inventory, authorized=a.authorized,
            **({"traffic_path": a.traffic} if a.traffic else {}),
            **({"workflow_manifest_path": a.workflow_manifest} if a.workflow_manifest else {}),
            **({"source_dir": a.source_dir} if a.source_dir else {}),
            **({"api_contract_path": a.api_contract} if a.api_contract else {}),
        )
        active = result.get("active_testing", {})
        status = active.get("status", "completed" if active else "skipped")
        findings = active.get("unique_findings", len(active.get("findings", [])))
        validation = result.get("validated_evidence", {}).get("counts", {})
        execution = result.get("agent_execution", {})
        print(
            f"Agent roles={execution.get('configured_roles', result.get('agent_count', 0))}; "
            f"model_mode={execution.get('mode', 'unknown')}; "
            f"model_analyzed={execution.get('successful_model_analyses', 0)}; "
            f"roles_skipped_without_model={execution.get('roles_skipped_without_local_model', 0)}; "
            f"tool_followups={execution.get('tool_followup_runs', 0)}/{execution.get('tool_followup_requests', 0)}; "
            f"active_testing={status}; candidate_findings={findings}; "
            f"evidence_backed={validation.get('evidence_backed', 0)}; "
            f"needs_review={validation.get('needs_review', 0)}. Reports: {a.out}"
        )
        return
    if a.cmd == "auto-run":
        result = run_target(
            a.target, a.rules, a.out, authorized=a.authorized,
            **({"traffic_path": a.traffic} if a.traffic else {}),
            **({"workflow_manifest_path": a.workflow_manifest} if a.workflow_manifest else {}),
            **({"source_dir": a.source_dir} if a.source_dir else {}),
            **({"api_contract_path": a.api_contract} if a.api_contract else {}),
        )
        active = result.get("active_testing", {})
        validation = result.get("validated_evidence", {}).get("counts", {})
        print(json.dumps({
            "target": a.target,
            "inventory_counts": result.get("inventory_counts", {}),
            "agent_roles_configured": result.get("agent_execution", {}).get("configured_roles", result.get("agent_count", 0)),
            "agent_execution": result.get("agent_execution", {}),
            "active_discovery_enabled": result.get("tool_plan", {}).get("active_discovery_enabled", False),
            "active_testing_status": active.get("status", "completed" if active else "skipped"),
            "candidate_findings_count": active.get("unique_findings", len(active.get("findings", []))),
            "evidence_backed_findings_count": validation.get("evidence_backed", 0),
            "needs_review_count": validation.get("needs_review", 0),
            "missing_tools": active.get("missing", 0),
            "out": a.out,
        }, indent=2))


    if a.cmd == "source-review":
        report = review_source(a.source_dir, a.out)
        print(json.dumps({key: report[key] for key in ("mode", "status", "file_count", "candidate_count", "truncated", "runtime_verified")}, indent=2))
        return


if __name__ == "__main__":
    sys.exit(main())
