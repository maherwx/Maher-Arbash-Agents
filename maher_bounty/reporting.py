from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path


def _esc(value):
    return html.escape(str(value or ""))


def _list_md(values):
    values = values or []
    return "\n".join(f"  - {v}" for v in values) if values else "  - None recorded"


def _validated_findings(payload):
    validation = payload.get("validated_evidence") or {}
    return list(validation.get("evidence_backed") or [])


def build_report_bundle(out_dir, payload, reviewed_findings, topology):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()

    active = payload.get("active_testing") or {}
    validation = payload.get("validated_evidence") or {}
    intelligence = payload.get("application_intelligence") or {}
    validated = _validated_findings(payload)

    bundle = dict(payload)
    bundle["generated_at_utc"] = generated
    bundle["architecture_topology"] = topology
    bundle["reviewed_findings"] = reviewed_findings
    bundle["validated_findings"] = validated
    bundle["report_schema_version"] = "3.0"
    (out / "report.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    counts = payload.get("inventory_counts", {})
    tool_runs = active.get("runs") or []

    md = [
        "# Maher Advanced Vulnerability Research Report",
        "",
        f"**Generated (UTC):** {generated}",
        f"**Program:** {payload.get('scope', {}).get('program', '')}",
        f"**Agents:** {payload.get('agent_count', 0)}",
        f"**Collaboration waves:** {len(payload.get('collaboration_waves', []))}",
        f"**Inventory:** {counts.get('hosts',0)} hosts / {counts.get('endpoints',0)} endpoints / {counts.get('http',0)} HTTP records",
        "",
        "## Executive summary",
        f"- Evidence-backed findings: {len(validated)}",
        f"- Needs review: {validation.get('counts',{}).get('needs_review',0)}",
        f"- Rejected / insufficient evidence: {validation.get('counts',{}).get('rejected',0)}",
        f"- Active tools registered: {active.get('registered',0)}",
        f"- Active tools executed: {active.get('executed',0)}",
        f"- Active tool timeouts: {active.get('timeouts',0)}",
        f"- Active tool failures: {active.get('failed',0)}",
        f"- Application endpoints modeled: {intelligence.get('endpoint_count',0)}",
        f"- API candidates: {len(intelligence.get('api_candidates',[]))}",
        f"- JavaScript assets: {len(intelligence.get('javascript_assets',[]))}",
        f"- Auth/session candidates: {len(intelligence.get('auth_state_candidates',[]))}",
        "",
        "## Evidence-backed findings",
    ]

    if not validated:
        md.append("No finding passed the current evidence-validation threshold.")
    for i, f in enumerate(validated, 1):
        md += [
            "",
            f"### {i}. {f.get('title','Untitled')}",
            f"- **Severity:** {str(f.get('severity','info')).upper()}",
            f"- **Target:** {f.get('target') or 'Not recorded'}",
            f"- **Validation state:** {f.get('validation_state')}",
            f"- **Validation score:** {f.get('validation_score',0)}",
            f"- **Independent sources:** {f.get('independent_sources',0)}",
            f"- **Sources:** {', '.join(f.get('sources',[])) or 'Unknown'}",
            f"- **Evidence:** {f.get('evidence') or 'Evidence recorded in JSON artifact'}",
            f"- **Fingerprint:** {f.get('fingerprint','')}",
        ]

    md += ["", "## Active testing telemetry"]
    if not tool_runs:
        md.append("No active tool runs recorded.")
    for run in tool_runs:
        md.append(f"- **{run.get('tool')}** — {run.get('status')}")

    md += ["", "## Application intelligence"]
    for key, label in (
        ("api_candidates","API candidates"),
        ("javascript_assets","JavaScript assets"),
        ("auth_state_candidates","Auth/session candidates"),
        ("upload_candidates","File-handling candidates"),
        ("identifier_parameters","Identifier parameters"),
    ):
        values = intelligence.get(key) or []
        md.append(f"- **{label}:** {len(values)}")

    md += ["", "## Architecture topology"]
    for host, node in topology.items():
        md.append(f"### {host}")
        md.append(f"- Observed URLs: {node.get('urls', 0)}")
        md.append(f"- Technologies: {', '.join(node.get('technologies', [])) or 'Unknown'}")
        md.append(f"- HTTP status codes: {', '.join(map(str, node.get('status_codes', []))) or 'None'}")

    md += ["", "## Agent-reviewed candidates"]
    if not reviewed_findings:
        md.append("No additional agent-reviewed candidates met the review pipeline.")
    for i, finding in enumerate(reviewed_findings, 1):
        md += [
            "",
            f"### Candidate {i}. {finding.get('title','Untitled')}",
            f"- **Target:** {finding.get('target') or 'Not recorded'}",
            f"- **Review status:** {finding.get('status')}",
            f"- **Evidence confidence:** {finding.get('confidence_score',0)}/100",
            f"- **Independent agents:** {finding.get('independent_agent_count',0)}",
        ]

    (out / "report.md").write_text("\n".join(md), encoding="utf-8")

    validated_rows = []
    for f in validated:
        validated_rows.append(
            "<tr>"
            f"<td>{_esc(f.get('title'))}</td>"
            f"<td>{_esc(str(f.get('severity','info')).upper())}</td>"
            f"<td>{_esc(f.get('target'))}</td>"
            f"<td>{_esc(f.get('validation_state'))}</td>"
            f"<td>{_esc(f.get('validation_score'))}</td>"
            f"<td>{_esc(', '.join(f.get('sources',[])))}</td>"
            "</tr>"
        )

    tool_rows = []
    for run in tool_runs:
        tool_rows.append(
            f"<tr><td>{_esc(run.get('tool'))}</td><td>{_esc(run.get('status'))}</td>"
            f"<td>{_esc(run.get('returncode'))}</td></tr>"
        )

    topology_rows = []
    for host, node in topology.items():
        topology_rows.append(
            f"<tr><td>{_esc(host)}</td><td>{node.get('urls',0)}</td>"
            f"<td>{_esc(', '.join(node.get('technologies', [])))}</td>"
            f"<td>{_esc(', '.join(map(str,node.get('status_codes', []))))}</td></tr>"
        )

    vcounts = validation.get("counts") or {}
    html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maher Advanced Research Report</title><style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#080d18;color:#e8edf7;margin:0}}main{{max-width:1280px;margin:auto;padding:32px}}h1,h2{{color:#fff}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}.card{{background:#111a2b;border:1px solid #24334f;border-radius:12px;padding:16px}}.n{{font-size:28px;font-weight:750}}table{{width:100%;border-collapse:collapse;background:#0e1626;margin-bottom:24px}}th,td{{padding:10px;border:1px solid #293653;text-align:left;vertical-align:top}}th{{background:#18223a}}.muted{{color:#aeb9cf}}.ok{{color:#8fe388}}.warn{{color:#ffd27a}}
</style></head><body><main>
<h1>Maher Advanced Vulnerability Research Report</h1>
<p class="muted">Generated UTC: {_esc(generated)} · Program: {_esc(payload.get('scope',{}).get('program',''))}</p>
<div class="grid">
<div class="card"><div class="n">{len(validated)}</div>Evidence-backed</div>
<div class="card"><div class="n">{vcounts.get('needs_review',0)}</div>Needs review</div>
<div class="card"><div class="n">{active.get('executed',0)}</div>Tools executed</div>
<div class="card"><div class="n">{active.get('timeouts',0)}</div>Timeouts</div>
<div class="card"><div class="n">{payload.get('agent_count',0)}</div>Agents</div>
<div class="card"><div class="n">{counts.get('endpoints',0)}</div>Endpoints</div>
</div>
<h2>Evidence-backed findings</h2>
<table><tr><th>Finding</th><th>Severity</th><th>Target</th><th>State</th><th>Score</th><th>Sources</th></tr>{''.join(validated_rows) or '<tr><td colspan="6">No finding passed the evidence-validation threshold.</td></tr>'}</table>
<h2>Active testing telemetry</h2>
<table><tr><th>Tool</th><th>Status</th><th>Return code</th></tr>{''.join(tool_rows) or '<tr><td colspan="3">No active tool runs recorded.</td></tr>'}</table>
<h2>Application intelligence</h2>
<div class="grid">
<div class="card"><div class="n">{len(intelligence.get('api_candidates',[]))}</div>API candidates</div>
<div class="card"><div class="n">{len(intelligence.get('javascript_assets',[]))}</div>JavaScript assets</div>
<div class="card"><div class="n">{len(intelligence.get('auth_state_candidates',[]))}</div>Auth/session candidates</div>
<div class="card"><div class="n">{len(intelligence.get('identifier_parameters',[]))}</div>Identifier parameters</div>
</div>
<h2>Architecture topology</h2>
<table><tr><th>Host</th><th>Observed URLs</th><th>Technologies</th><th>Status codes</th></tr>{''.join(topology_rows) or '<tr><td colspan="4">No topology collected.</td></tr>'}</table>
<h2>Methodology</h2>
<p>Authorized, non-destructive active testing with application intelligence, normalized evidence, independent-source correlation, validation scoring and agent review. Tool output is evidence, not automatic confirmation.</p>
</main></body></html>'''
    (out / "report.html").write_text(html_doc, encoding="utf-8")
    return bundle
