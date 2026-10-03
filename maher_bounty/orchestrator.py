from pathlib import Path
import json
import os
import yaml
from .model_adapter import LocalModelAdapter


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
    """Keep model context useful without flooding a local model."""
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
    model = LocalModelAdapter()

    results = []
    for agent in load_agents():
        results.append(model.analyze(agent, {
            "scope": scope,
            "rules": rules,
            "inventory": context_inventory,
        }))

    payload = {
        "scope": scope,
        "rules": rules,
        "inventory_counts": inventory.get("counts", {}),
        "inventory_source": inventory.get("source_file"),
        "agent_count": len(results),
        "results": results,
    }
    (out / "report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    counts = inventory.get("counts", {})
    md = [
        "# Maher Vulnerability Research Report",
        f"\nAgents: {len(results)}",
        f"\nProgram: {scope.get('program', '')}",
        f"\nInventory: {counts.get('hosts', 0)} hosts / {counts.get('endpoints', 0)} endpoints / {counts.get('http', 0)} HTTP records",
        "\n## Agent passes",
    ]
    md += [f"- **{r['agent']}** — {r['status']}" for r in results]
    (out / "report.md").write_text("\n".join(md), encoding="utf-8")

    rows = "".join(f"<tr><td>{r['agent']}</td><td>{r['status']}</td></tr>" for r in results)
    html = f'''<!doctype html><meta charset="utf-8"><title>Maher Report</title><h1>Maher Vulnerability Research Report</h1><p>Program: {scope.get("program", "")}</p><p>Agents: {len(results)}</p><p>Inventory: {counts.get("hosts",0)} hosts / {counts.get("endpoints",0)} endpoints / {counts.get("http",0)} HTTP records</p><table><tr><th>Agent</th><th>Status</th></tr>{rows}</table>'''
    (out / "report.html").write_text(html, encoding="utf-8")
    return payload
