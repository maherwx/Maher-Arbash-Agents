from pathlib import Path
import json, yaml
from .model_adapter import LocalModelAdapter

def load_agents():
    p=Path(__file__).parent/"agents"
    return [json.loads(x.read_text(encoding="utf-8")) for x in sorted(p.glob("*.json"))]

def run(scope_path, rules_path, out_dir="reports"):
    scope=yaml.safe_load(Path(scope_path).read_text(encoding="utf-8"))
    rules=yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
    if not rules.get("authorization_required", True):
        raise SystemExit("rules.yaml must keep authorization_required=true")
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    model=LocalModelAdapter()
    results=[model.analyze(a,{"scope":scope,"rules":rules}) for a in load_agents()]
    payload={"scope":scope,"rules":rules,"agent_count":len(results),"results":results}
    (out/"report.json").write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    md=["# Maher Vulnerability Research Report",f"\nAgents: {len(results)}",f"\nProgram: {scope.get('program','')}","\n## Agent passes"]
    md += [f"- **{r['agent']}** — {r['status']}" for r in results]
    (out/"report.md").write_text("\n".join(md),encoding="utf-8")
    rows="".join(f"<tr><td>{r['agent']}</td><td>{r['status']}</td></tr>" for r in results)
    html=f'''<!doctype html><meta charset="utf-8"><title>Maher Report</title><h1>Maher Vulnerability Research Report</h1><p>Program: {scope.get("program","")}</p><p>Agents: {len(results)}</p><table><tr><th>Agent</th><th>Status</th></tr>{rows}</table>'''
    (out/"report.html").write_text(html,encoding="utf-8")
    return payload
