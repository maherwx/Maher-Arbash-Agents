from collections import Counter
from pathlib import Path
import json
import os
import re
import yaml
from .model_adapter import LocalModelAdapter
from .hypothesis_engine import build_hypotheses
from .collaboration import build_waves, evidence_bus
from .research_intelligence import architecture_map, review_findings, research_directives
from .reporting import build_report_bundle
from .knowledge_graph import build_application_graph
from .persistence import ResearchStore
from .native_engines import run_native_engines
from .tool_orchestration import collect_target_inventory
from .active_testing import run_active_testing, _dedupe
from .agent_tool_router import build_local_tool_requests
from .agent_feedback import run_agent_tool_feedback as run_agent_tool_requests
from .scope_policy import scope_seed_targets
from .traffic_ingest import ingest_traffic
from .burp_evidence import build_scoped_traffic_evidence, build_traffic_target_references
from .advanced_analysis import build_application_intelligence, normalize_evidence, validate_evidence, build_agent_workstreams, write_advanced_artifacts
from .advanced_web_tools import run_advanced_web_tools
from .workflow_execution import execute_workflows, validate_manifest
from .source_review import review_source
from .source_correlation import correlate_source_traffic
from .artifact_io import write_json_atomic
from .source_check_plan import build_source_check_plan, audit_source_checks


def load_agents():
    p = Path(__file__).parent / "agents"
    return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(p.glob("*.json"))]


def load_inventory(scope, explicit_path=None):
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    env_path = os.getenv("MAHER_INVENTORY", "").strip()
    if env_path:
        candidates.append(Path(env_path))
    configured = scope.get("inventory") if isinstance(scope, dict) else None
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path("results/inventory.json"))
    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    data["source_file"] = str(path)
                    return data
            except (OSError, json.JSONDecodeError):
                pass
    return {"counts": {"hosts": 0, "endpoints": 0, "http": 0}, "hosts": [], "endpoints": [], "http": []}


def _merge_inventories(parts, out_file):
    merged = {"hosts": [], "endpoints": [], "http": []}
    seen = {key: set() for key in merged}
    plans = []
    for part in parts:
        for key, identity in (("hosts", "value"), ("endpoints", "value"), ("http", "url")):
            for row in part.get(key, []):
                marker = row.get(identity) if isinstance(row, dict) else row
                if marker is not None and marker not in seen[key]:
                    seen[key].add(marker)
                    merged[key].append(row)
        if part.get("tool_plan"):
            plans.append(part["tool_plan"])
    merged["counts"] = {key: len(merged[key]) for key in ("hosts", "endpoints", "http")}
    merged["tool_plan"] = {
        "active_discovery_enabled": any(x.get("active_discovery_enabled", False) for x in plans),
        "seed_targets": [x.get("target") for x in plans],
        "selected": sorted({tool for x in plans for tool in x.get("selected", [])}),
        "skipped": [row for x in plans for row in x.get("skipped", [])],
        "runs": [row for x in plans for row in x.get("runs", [])],
        "metadata_runs": [row for x in plans for row in x.get("metadata_runs", [])],
        "out_of_scope_hosts_filtered": sum(x.get("out_of_scope_hosts_filtered", 0) for x in plans),
    }
    merged["source_file"] = str(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return merged


def _collect_scope_inventory(scope, rules, target, out_dir):
    seeds = scope_seed_targets(scope, target=target)
    parts = []
    for index, seed in enumerate(seeds, start=1):
        host = re.sub(r"[^A-Za-z0-9._-]", "_", seed.split("://", 1)[-1])
        part = collect_target_inventory(seed, out_dir / f"{index:03d}-{host}", rules=rules, scope=scope)
        parts.append(part)
    if not parts:
        return load_inventory(scope)
    return _merge_inventories(parts, out_dir / "inventory.json")


def compact_inventory(inventory, max_items=250):
    return {"counts": inventory.get("counts", {}), "hosts": inventory.get("hosts", [])[:max_items], "endpoints": inventory.get("endpoints", [])[:max_items], "http": inventory.get("http", [])[:max_items], "source_file": inventory.get("source_file"), "target": inventory.get("target"), "tool_plan": inventory.get("tool_plan", {})}


def active_discovery_enabled(rules: dict, *, authorized: bool) -> bool:
    configured = rules.get("allow_active_discovery")
    return bool(authorized) if configured is None else bool(configured)


def _run_loaded(scope: dict, rules: dict, out_dir="reports", inventory_path=None, target=None, *, authorized=False, traffic_path=None, workflow_manifest_path=None, source_dir=None):
    if not rules.get("authorization_required", True):
        raise SystemExit("rules.yaml must keep authorization_required=true")
    active_enabled = active_discovery_enabled(rules, authorized=authorized)
    if active_enabled and not authorized:
        raise SystemExit("active discovery requires --authorized to confirm permission for the listed scope")
    rules = dict(rules)
    rules["allow_active_discovery"] = active_enabled
    if workflow_manifest_path and (not authorized or not active_enabled):
        raise ValueError("workflow execution requires authorized active testing")
    scope = dict(scope or {})
    scope.setdefault("program", "Authorized target assessment")
    if target and not scope.get("assets"):
        scope["assets"] = [target]
    scope.setdefault("out_of_scope", [])
    workflow_manifest = None
    if workflow_manifest_path:
        workflow_manifest = json.loads(Path(workflow_manifest_path).read_text(encoding="utf-8"))
        validate_manifest(workflow_manifest, scope)
    imported_traffic = ingest_traffic(traffic_path, kind="auto") if traffic_path else None
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    store = ResearchStore()
    run_id = store.create_run(scope)
    try:
        source_review = review_source(source_dir, out / "source") if source_dir else {"mode": "not_run", "findings": [], "files": []}
        if source_dir:
            store.checkpoint(run_id, "source_review", source_review)
        inventory = load_inventory(scope, inventory_path)
        if not inventory_path:
            seeds = scope_seed_targets(scope, target=target)
            if seeds:
                print(f"[recon] Collecting inventory for {len(seeds)} scope seed(s)", flush=True)
                inventory = _collect_scope_inventory(scope, rules, target, out / "recon")
        traffic_target_refs = {}
        traffic_evidence = {
            "source": "burp_or_har_import", "records": [], "record_count": 0,
            "out_of_scope_records_filtered": 0, "truncated": False,
            "advanced_analysis": {},
        }
        if traffic_path:
            traffic_evidence = build_scoped_traffic_evidence(imported_traffic, scope)
            traffic_target_refs = build_traffic_target_references(imported_traffic, scope)
            allowed_traffic_urls = set(traffic_target_refs.values())
            scoped_traffic = [row for row in imported_traffic if row.get("url") in allowed_traffic_urls]
            advanced_analysis = run_advanced_web_tools(scoped_traffic)
            traffic_evidence["advanced_analysis"] = advanced_analysis
            (out / "advanced-traffic-tools.json").write_text(
                json.dumps(advanced_analysis, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            store.checkpoint(run_id, "advanced_web_tools", advanced_analysis)
            (out / "burp-traffic-evidence.json").write_text(
                json.dumps(traffic_evidence, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            store.checkpoint(run_id, "burp_traffic_evidence", traffic_evidence)

        if source_dir:
            correlation = correlate_source_traffic(source_review, traffic_evidence, traffic_target_refs, scope)
            source_review = {**{key: value for key, value in source_review.items() if key != "artifact_generation"},
                             "static_artifact_generation": source_review.get("artifact_generation"),
                             "traffic_correspondence": correlation}
            write_json_atomic(out / "source" / "source-traffic-correspondence.json", correlation)
            store.checkpoint(run_id, "source_traffic_correspondence", correlation)

        active_testing = {"status": "skipped", "reason": "allow_active_discovery=false", "findings": []}
        if active_enabled:
            print("[active] Testing all authorized assets discovered in scope", flush=True)
            (out / "active").mkdir(parents=True, exist_ok=True)
            active_testing = run_active_testing(target, inventory, out / "active", scope=scope)
            store.checkpoint(run_id, "active_testing", active_testing)
        else:
            print("[active] SKIPPED: rules.yaml has allow_active_discovery=false; reports contain hypotheses only.", flush=True)

        workflow_execution = {"status": "requires_input", "reason": "no workflow manifest supplied", "findings": []}
        if workflow_manifest_path:
            print("[workflows] Executing identity access matrix and application invariants", flush=True)
            workflow_execution = execute_workflows(
                workflow_manifest, scope,
                out / "workflows", authorized=authorized,
            )
            active_testing["findings"] = _dedupe([*active_testing.get("findings", []), *workflow_execution["findings"]])
            active_testing["unique_findings"] = len(active_testing["findings"])
            store.checkpoint(run_id, "workflow_execution", workflow_execution)
        active_testing["workflow_execution"] = workflow_execution

        print("[intelligence] Building application model and evidence graph", flush=True)
        intelligence_target = target or inventory.get("target") or ""
        intelligence = build_application_intelligence(intelligence_target, inventory)
        normalized = normalize_evidence(active_testing)
        validation = validate_evidence(normalized)
        workstreams = build_agent_workstreams(intelligence, validation)
        write_advanced_artifacts(out / "intelligence", intelligence, validation, workstreams)
        store.checkpoint(run_id, "application_intelligence", intelligence)
        store.checkpoint(run_id, "validated_evidence", validation)
        print(f"[validation] evidence-backed={validation['counts']['evidence_backed']} review={validation['counts']['needs_review']} rejected={validation['counts']['rejected']}", flush=True)

        print("[analysis] Building hypotheses and application graph", flush=True)
        context_inventory = compact_inventory(inventory)
        hypotheses = build_hypotheses(context_inventory)
        topology = architecture_map(context_inventory)
        graph = build_application_graph(context_inventory, hypotheses)
        directives = research_directives()
        store.checkpoint(run_id, "inventory", context_inventory)
        store.checkpoint(run_id, "hypotheses", hypotheses)
        store.checkpoint(run_id, "application_graph", graph)
        native = {}
        source_file = inventory.get("source_file")
        if source_file and Path(source_file).is_file():
            native = run_native_engines(source_file)
            store.checkpoint(run_id, "native_engines", native)

        model = LocalModelAdapter()
        agents = load_agents()
        waves = build_waves(agents)
        results = []
        wave_summary = []
        if model.enabled:
            print(f"[agents] Running {len(agents)} specialist roles in {len(waves)} collaboration waves; mode={model.mode}", flush=True)
            for wave_index, wave in enumerate(waves, start=1):
                print(f"[agents] Wave {wave_index}/{len(waves)}: {len(wave)} agents", flush=True)
                prior_evidence = evidence_bus(results)
                current = []
                for agent in wave:
                    result = model.analyze(agent, {
                        "scope": scope, "rules": rules, "inventory": context_inventory,
                        "architecture_topology": topology, "application_graph": graph,
                        "application_intelligence": intelligence, "agent_workstreams": workstreams,
                        "validated_evidence": validation, "native_engine_analysis": native,
                        "source_review": source_review,
                        "traffic_evidence": traffic_evidence,
                        "active_testing": active_testing, "active_findings": active_testing.get("findings", []),
                        "hypotheses": hypotheses, "prior_agent_evidence": prior_evidence,
                        "research_directives": directives,
                        "research_method": {"mode": "collaborative_evidence_driven", "wave": wave_index, "principles": directives["directives"]},
                    })
                    current.append(result)
                    store.add_evidence(run_id, result.get("agent", "unknown"), "agent_result", result)
                results.extend(current)
                wave_summary.append({"wave": wave_index, "agents": [r.get("agent") for r in current], "shared_evidence_packets_after_wave": len(evidence_bus(results))})
                store.checkpoint(run_id, f"wave_{wave_index}", current)
        else:
            print(
                f"[agents] Local model unavailable; skipped {len(agents)} LLM analyses. "
                "The deterministic local tool coordinator remains available.",
                flush=True,
            )

        followup_summary = {"mode": "not_run", "runs": [], "findings": [], "decisions": []}
        local_tool_plan = {"agent_results": [], "request_count": 0, "mode": "not_run"}
        source_tool_plan = {"agent_results": [], "tasks": [], "mode": "not_run"}
        source_tool_audit = {"mode": "not_run", "tasks": []}
        def review_execution_round(packet):
            # Each specialist sees actual runs plus reviews from earlier peers.
            round_active = {**active_testing, "agent_tool_followups": packet}
            round_active["findings"] = _dedupe([*active_testing.get("findings", []), *packet["findings"]])
            round_validation = validate_evidence(normalize_evidence(round_active))
            round_inventory = {**context_inventory,
                               "endpoints": [{"value": url} for url in packet["known_urls"][:120]]}
            reviewers = {"web_surface_reviewer", "xss_surface_reviewer", "rest_reviewer", "evidence_reviewer"}
            reviews = []
            for specialist in agents:
                if specialist.get("id") not in reviewers:
                    continue
                review = model.analyze(specialist, {
                    "scope": scope, "rules": rules, "inventory": round_inventory,
                    "application_intelligence": intelligence, "validated_evidence": round_validation,
                    "active_testing": round_active, "active_findings": round_active["findings"],
                    "traffic_evidence": traffic_evidence, "prior_agent_evidence": evidence_bus(results),
                    "execution_feedback": packet, "research_directives": directives,
                    "source_review": source_review,
                    "source_check_plan": {key: value for key, value in source_tool_plan.items() if key != "agent_results"},
                    "research_method": {"mode": "execution_round_review", "round": packet["round"],
                                        "can_schedule_next_round": packet["can_schedule_next_round"]},
                })
                results.append(review)
                reviews.append(review)
                store.add_evidence(run_id, review.get("agent", "unknown"), "execution_round_review", review)
            store.checkpoint(run_id, f"execution_round_{packet['round']}_reviews", reviews)
            return reviews
        if active_enabled:
            known_followup_urls = [
                *active_testing.get("discovered_in_scope_urls", []),
                *traffic_target_refs.values(),
            ]
            local_tool_plan = build_local_tool_requests(
                known_followup_urls,
                scope=scope,
                active_testing=active_testing,
                tool_plan=inventory.get("tool_plan", {}),
            )
            if source_dir:
                source_tool_plan = build_source_check_plan(source_review, traffic_evidence, traffic_target_refs,
                    known_followup_urls, scope, active_testing, inventory.get("tool_plan", {}))
            followup_summary = run_agent_tool_requests(
                [*source_tool_plan["agent_results"], *results, *local_tool_plan["agent_results"]],
                known_followup_urls,
                out / "active" / "agent-followups",
                scope=scope,
                active_testing=active_testing,
                tool_plan=inventory.get("tool_plan", {}),
                target_references=traffic_target_refs,
                checkpoint_path=out / "active" / "agent-followups" / "execution-state.json",
                checkpoint_context=rules,
                **({"reviewer": review_execution_round} if model.enabled else {}),
            )
            followup_summary["planner_mode"] = (
                "local_model_plus_deterministic_coordinator" if model.enabled
                else "local_deterministic_coordinator"
            )
            if source_dir:
                source_tool_audit = audit_source_checks(source_tool_plan, followup_summary, traffic_target_refs)
                write_json_atomic(out / "source" / "source-check-plan.json",
                    {key: value for key, value in source_tool_plan.items() if key != "agent_results"})
                write_json_atomic(out / "source" / "source-check-audit.json", source_tool_audit)
                store.checkpoint(run_id, "source_check_admission_audit", source_tool_audit)
            followup_summary["deterministic_plan"] = {
                key: value for key, value in local_tool_plan.items() if key != "agent_results"
            }
            active_testing["agent_tool_followups"] = followup_summary
            (out / "active" / "agent-followups.json").write_text(
                json.dumps(followup_summary, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            store.checkpoint(run_id, "agent_tool_followups", followup_summary)
            if followup_summary.get("findings"):
                active_testing["findings"] = _dedupe([
                    *active_testing.get("findings", []),
                    *followup_summary["findings"],
                ])
                normalized = normalize_evidence(active_testing)
                validation = validate_evidence(normalized)
                workstreams = build_agent_workstreams(intelligence, validation)
                write_advanced_artifacts(out / "intelligence", intelligence, validation, workstreams)
                store.checkpoint(run_id, "validated_evidence_after_followups", validation)
                review_ids = {"evidence_reviewer", "false_positive_reviewer", "reproducibility_reviewer"}
                prior_evidence = evidence_bus(results)
                followup_reviews = []
                if model.enabled:
                    for reviewer in agents:
                        if reviewer.get("id") not in review_ids:
                            continue
                        review = model.analyze(reviewer, {
                            "scope": scope, "rules": rules, "inventory": context_inventory,
                            "architecture_topology": topology, "application_graph": graph,
                            "application_intelligence": intelligence, "agent_workstreams": workstreams,
                            "validated_evidence": validation, "native_engine_analysis": native,
                            "source_review": source_review,
                            "source_check_admission_audit": source_tool_audit,
                            "traffic_evidence": traffic_evidence,
                            "active_testing": active_testing, "active_findings": active_testing.get("findings", []),
                            "hypotheses": hypotheses, "prior_agent_evidence": prior_evidence,
                            "research_directives": directives,
                            "research_method": {"mode": "followup_evidence_review", "principles": directives["directives"]},
                        })
                        results.append(review)
                        followup_reviews.append(review)
                        store.add_evidence(run_id, review.get("agent", "unknown"), "followup_review", review)
                store.checkpoint(run_id, "followup_reviews", followup_reviews)
        else:
            active_testing["agent_tool_followups"] = {
                **followup_summary,
                "reason": "active testing is disabled by the authorized run configuration",
            }

        agent_status_counts = Counter(str(row.get("status", "unknown")) for row in results)
        agent_execution = {
            "mode": model.mode,
            "configured_roles": len(agents),
            "analysis_calls": len(results),
            "successful_model_analyses": sum(1 for row in results if row.get("status") not in {"planned", "model_error"}),
            "planning_only": agent_status_counts.get("planned", 0),
            "roles_skipped_without_local_model": len(agents) if not model.enabled else 0,
            "model_errors": agent_status_counts.get("model_error", 0),
            "tool_followup_mode": followup_summary.get("planner_mode", "not_run"),
            "tool_followup_requests": followup_summary.get("request_count", 0),
            "tool_followup_runs": len(followup_summary.get("runs", [])),
            "status_counts": dict(agent_status_counts),
        }

        print("[report] Reviewing findings and building report bundle", flush=True)
        reviewed_findings = review_findings(results)
        store.save_findings(run_id, reviewed_findings)
        payload = {
            "run_id": run_id, "scope": scope, "rules": rules,
            "inventory_counts": inventory.get("counts", {}),
            "inventory_source": source_file, "tool_plan": inventory.get("tool_plan", {}),
            "active_testing": active_testing, "burp_traffic_evidence": traffic_evidence,
            "workflow_execution": workflow_execution,
            "source_review": source_review,
            "source_check_plan": {key: value for key, value in source_tool_plan.items() if key != "agent_results"},
            "source_check_admission_audit": source_tool_audit,
            "application_intelligence": intelligence,
            "validated_evidence": validation, "agent_workstreams": workstreams,
            "hypothesis_count": len(hypotheses), "hypotheses": hypotheses,
            "application_graph_stats": graph.get("stats", {}), "native_engines": native,
            "collaboration_waves": wave_summary, "agent_count": len(results),
            "agent_execution": agent_execution, "results": results,
        }
        build_report_bundle(out, payload, reviewed_findings, topology)
        (out / "application-graph.json").write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
        store.finish(run_id)
        print(
            f"[done] Agent analysis mode={agent_execution['mode']} "
            f"model_analyzed={agent_execution['successful_model_analyses']} "
            f"planning_only={agent_execution['planning_only']} "
            f"model_errors={agent_execution['model_errors']}. Reports: {out}",
            flush=True,
        )
        return payload
    except Exception:
        store.finish(run_id, "failed")
        raise
    finally:
        store.db.close()


def run(scope_path, rules_path, out_dir="reports", inventory_path=None, *, authorized=False, traffic_path=None, workflow_manifest_path=None, source_dir=None):
    scope = yaml.safe_load(Path(scope_path).read_text(encoding="utf-8"))
    rules = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
    return _run_loaded(scope, rules, out_dir, inventory_path, authorized=authorized, traffic_path=traffic_path, workflow_manifest_path=workflow_manifest_path, source_dir=source_dir)


def run_target(target: str, rules_path: str | None = None, out_dir="results/auto", *, authorized=False, traffic_path=None, workflow_manifest_path=None, source_dir=None):
    if not authorized:
        raise SystemExit("auto-run requires --authorized to confirm permission for this target")
    rules = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) if rules_path else {
        "authorization_required": True, "respect_out_of_scope": True,
        "no_destructive_testing": True, "no_denial_of_service": True,
        "no_persistence": True, "report_evidence": True,
        "allow_active_discovery": True,
    }
    return _run_loaded({"program": "Authorized target assessment", "assets": [target], "out_of_scope": []}, rules, out_dir, target=target, authorized=True, traffic_path=traffic_path, workflow_manifest_path=workflow_manifest_path, source_dir=source_dir)
