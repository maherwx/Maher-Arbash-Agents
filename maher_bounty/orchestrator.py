from pathlib import Path
import json
import os
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
from .active_testing import run_active_testing
from .advanced_analysis import build_application_intelligence, normalize_evidence, validate_evidence, build_agent_workstreams, write_advanced_artifacts


def load_agents():
    p=Path(__file__).parent/"agents"
    return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(p.glob("*.json"))]


def load_inventory(scope, explicit_path=None):
    candidates=[]
    if explicit_path: candidates.append(Path(explicit_path))
    env_path=os.getenv("MAHER_INVENTORY","").strip()
    if env_path: candidates.append(Path(env_path))
    configured=scope.get("inventory") if isinstance(scope,dict) else None
    if configured: candidates.append(Path(configured))
    candidates.append(Path("results/inventory.json"))
    for path in candidates:
        if path.is_file():
            try:
                data=json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data,dict):
                    data["source_file"]=str(path); return data
            except (OSError,json.JSONDecodeError): pass
    return {"counts":{"hosts":0,"endpoints":0,"http":0},"hosts":[],"endpoints":[],"http":[]}


def compact_inventory(inventory,max_items=250):
    return {"counts":inventory.get("counts",{}),"hosts":inventory.get("hosts",[])[:max_items],"endpoints":inventory.get("endpoints",[])[:max_items],"http":inventory.get("http",[])[:max_items],"source_file":inventory.get("source_file"),"target":inventory.get("target"),"tool_plan":inventory.get("tool_plan",{})}


def _run_loaded(scope:dict,rules:dict,out_dir="reports",inventory_path=None,target=None):
    if not rules.get("authorization_required",True): raise SystemExit("rules.yaml must keep authorization_required=true")
    if target:
        scope=dict(scope or {}); scope.setdefault("program","Authorized target assessment"); scope["assets"]=[target]
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    store=ResearchStore(); run_id=store.create_run(scope)
    try:
        inventory=load_inventory(scope,inventory_path); active_testing={}
        if target and not inventory_path:
            recon_dir=out/"recon"; inventory=collect_target_inventory(target,recon_dir,rules=rules); inventory["source_file"]=str(recon_dir/"inventory.json")
            if rules.get("allow_active_discovery",False):
                print("[active] Starting authorized non-destructive testing",flush=True)
                active_testing=run_active_testing(target,inventory,out/"active",scope=scope); store.checkpoint(run_id,"active_testing",active_testing)
            else: print("[active] Disabled by rules",flush=True)

        print("[intelligence] Building application model and evidence graph",flush=True)
        intelligence=build_application_intelligence(target or (scope.get("assets") or [""])[0],inventory)
        normalized=normalize_evidence(active_testing)
        validation=validate_evidence(normalized)
        workstreams=build_agent_workstreams(intelligence,validation)
        write_advanced_artifacts(out/"intelligence",intelligence,validation,workstreams)
        store.checkpoint(run_id,"application_intelligence",intelligence); store.checkpoint(run_id,"validated_evidence",validation)
        print(f"[validation] evidence-backed={validation['counts']['evidence_backed']} review={validation['counts']['needs_review']} rejected={validation['counts']['rejected']}",flush=True)

        print("[analysis] Building hypotheses and application graph",flush=True)
        context_inventory=compact_inventory(inventory); hypotheses=build_hypotheses(context_inventory); topology=architecture_map(context_inventory); graph=build_application_graph(context_inventory,hypotheses); directives=research_directives()
        store.checkpoint(run_id,"inventory",context_inventory); store.checkpoint(run_id,"hypotheses",hypotheses); store.checkpoint(run_id,"application_graph",graph)
        native={}; source_file=inventory.get("source_file")
        if source_file and Path(source_file).is_file(): native=run_native_engines(source_file); store.checkpoint(run_id,"native_engines",native)

        model=LocalModelAdapter(); agents=load_agents(); waves=build_waves(agents)
        print(f"[agents] Starting {len(agents)} agents in {len(waves)} collaboration waves",flush=True)
        results=[]; wave_summary=[]
        for wave_index,wave in enumerate(waves,start=1):
            print(f"[agents] Wave {wave_index}/{len(waves)}: {len(wave)} agents",flush=True); prior_evidence=evidence_bus(results); current=[]
            for agent in wave:
                result=model.analyze(agent,{"scope":scope,"rules":rules,"inventory":context_inventory,"architecture_topology":topology,"application_graph":graph,"application_intelligence":intelligence,"agent_workstreams":workstreams,"validated_evidence":validation,"native_engine_analysis":native,"active_testing":active_testing,"active_findings":active_testing.get("findings",[]),"hypotheses":hypotheses,"prior_agent_evidence":prior_evidence,"research_directives":directives,"research_method":{"mode":"collaborative_evidence_driven","wave":wave_index,"principles":directives["directives"]}})
                current.append(result); store.add_evidence(run_id,result.get("agent","unknown"),"agent_result",result)
            results.extend(current); wave_summary.append({"wave":wave_index,"agents":[r.get("agent") for r in current],"shared_evidence_packets_after_wave":len(evidence_bus(results))}); store.checkpoint(run_id,f"wave_{wave_index}",current)

        print("[report] Reviewing findings and building report bundle",flush=True)
        reviewed_findings=review_findings(results); store.save_findings(run_id,reviewed_findings)
        payload={"run_id":run_id,"scope":scope,"rules":rules,"inventory_counts":inventory.get("counts",{}),"inventory_source":source_file,"tool_plan":inventory.get("tool_plan",{}),"active_testing":active_testing,"application_intelligence":intelligence,"validated_evidence":validation,"agent_workstreams":workstreams,"hypothesis_count":len(hypotheses),"hypotheses":hypotheses,"application_graph_stats":graph.get("stats",{}),"native_engines":native,"collaboration_waves":wave_summary,"agent_count":len(results),"results":results}
        build_report_bundle(out,payload,reviewed_findings,topology); (out/"application-graph.json").write_text(json.dumps(graph,ensure_ascii=False,indent=2),encoding="utf-8"); store.finish(run_id)
        print(f"[done] Completed {len(results)} agent passes. Reports: {out}",flush=True); return payload
    except Exception:
        store.finish(run_id,"failed"); raise


def run(scope_path,rules_path,out_dir="reports",inventory_path=None):
    return _run_loaded(yaml.safe_load(Path(scope_path).read_text(encoding="utf-8")),yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")),out_dir,inventory_path)


def run_target(target:str,rules_path:str|None=None,out_dir="results/auto",*,authorized=False):
    if not authorized: raise SystemExit("auto-run requires --authorized to confirm permission for the supplied target")
    rules=yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) if rules_path else {"authorization_required":True,"respect_out_of_scope":True,"no_destructive_testing":True,"no_denial_of_service":True,"no_persistence":True,"report_evidence":True,"allow_active_discovery":True}
    return _run_loaded({"program":"Authorized target assessment","assets":[target],"out_of_scope":[]},rules,out_dir,target=target)
