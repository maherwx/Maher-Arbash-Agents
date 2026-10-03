from pathlib import Path
import json
import os
import yaml
from .model_adapter import LocalModelAdapter
from .hypothesis_engine import build_hypotheses
from .collaboration import build_waves, evidence_bus
from .research_intelligence import architecture_map, review_findings, research_directives
from .reporting import build_report_bundle


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


def compact_inventory(inventory, max_items=250):
    return {
        "counts": inventory.get("counts", {}),
        "hosts": inventory.get("hosts", [])[:max_items],
        "endpoints": inventory.get("endpoints", [])[:max_items],
        "http": inventory.get("http", [])[:max_items],
        "source_file": inventory.get("source_file"),
    }


def run(scope_path, rules_path, out_dir="reports", inventory_path=None):
    scope = yaml.safe_load(Path(scope_path).read_text(encoding="utf-8"))
    rules = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
    if not rules.get("authorization_required", True):
        raise SystemExit("rules.yaml must keep authorization_required=true")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    inventory = load_inventory(scope, inventory_path)
    context_inventory = compact_inventory(inventory)
    hypotheses = build_hypotheses(context_inventory)
    topology = architecture_map(context_inventory)
    directives = research_directives()
    model = LocalModelAdapter()

    agents = load_agents()
    waves = build_waves(agents)
    results = []
    wave_summary = []

    for wave_index, wave in enumerate(waves, start=1):
        prior_evidence = evidence_bus(results)
        current = []
        for agent in wave:
            result = model.analyze(agent, {
                "scope": scope,
                "rules": rules,
                "inventory": context_inventory,
                "architecture_topology": topology,
                "hypotheses": hypotheses,
                "prior_agent_evidence": prior_evidence,
                "research_directives": directives,
                "research_method": {
                    "mode": "collaborative_hypothesis_driven",
                    "wave": wave_index,
                    "principles": directives["directives"],
                },
            })
            current.append(result)
        results.extend(current)
        wave_summary.append({
            "wave": wave_index,
            "agents": [r.get("agent") for r in current],
            "shared_evidence_packets_after_wave": len(evidence_bus(results)),
        })

    reviewed_findings = review_findings(results)
    payload = {
        "scope": scope,
        "rules": rules,
        "inventory_counts": inventory.get("counts", {}),
        "inventory_source": inventory.get("source_file"),
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "collaboration_waves": wave_summary,
        "agent_count": len(results),
        "results": results,
    }
    build_report_bundle(out, payload, reviewed_findings, topology)
    return payload
