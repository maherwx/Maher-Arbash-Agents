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


def build_report_bundle(out_dir, payload, reviewed_findings, topology):
    """Produce analyst-grade JSON, Markdown and standalone HTML reports."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()

    bundle = dict(payload)
    bundle["generated_at_utc"] = generated
    bundle["architecture_topology"] = topology
    bundle["reviewed_findings"] = reviewed_findings
    bundle["report_schema_version"] = "2.0"
    (out / "report.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    counts = payload.get("inventory_counts", {})
    md = [
        "# Maher Advanced Vulnerability Research Report",
        "",
        f"**Generated (UTC):** {generated}",
        f"**Program:** {payload.get('scope', {}).get('program', '')}",
        f"**Agents:** {payload.get('agent_count', 0)}",
        f"**Collaboration waves:** {len(payload.get('collaboration_waves', []))}",
        f"**Research hypotheses:** {payload.get('hypothesis_count', 0)}",
        f"**Inventory:** {counts.get('hosts',0)} hosts / {counts.get('endpoints',0)} endpoints / {counts.get('http',0)} HTTP records",
        "",
        "## Executive research summary",
        f"- Reviewed candidate findings: {len(reviewed_findings)}",
        f"- Validation-priority candidates: {sum(1 for x in reviewed_findings if x.get('status') == 'validation_priority')}",
        f"- Candidates requiring conflict resolution: {sum(1 for x in reviewed_findings if x.get('status') == 'needs_conflict_resolution')}",
        f"- Architecture nodes mapped: {len(topology)}",
        "",
        "## Architecture / attack-surface topology",
    ]
    for host, node in topology.items():
        md.append(f"### {host}")
        md.append(f"- Observed URLs: {node.get('urls', 0)}")
        md.append(f"- Technologies: {', '.join(node.get('technologies', [])) or 'Unknown'}")
        md.append(f"- HTTP status codes: {', '.join(map(str, node.get('status_codes', []))) or 'None'}")
        if node.get("titles"):
            md.append(f"- Titles: {', '.join(node['titles'])}")

    md += ["", "## Prioritized candidate findings"]
    if not reviewed_findings:
        md.append("No candidate findings met the current evidence pipeline.")
    for i, finding in enumerate(reviewed_findings, 1):
        md += [
            "",
            f"### {i}. {finding.get('title','Untitled')}",
            f"- **Target:** {finding.get('target') or 'Not recorded'}",
            f"- **Review status:** {finding.get('status')}",
            f"- **Evidence confidence:** {finding.get('confidence_score',0)}/100",
            f"- **Independent agents:** {finding.get('independent_agent_count',0)}",
            "- **Impact signals:**",
            _list_md(finding.get("impact_signals")),
            "- **Evidence:**",
            _list_md(finding.get("evidence")),
            "- **Contradictions / uncertainty:**",
            _list_md(finding.get("contradictions")),
            "- **Reporting gate:** Candidate only until reproducible expected-vs-observed behavior and security impact are documented.",
        ]

    md += ["", "## Hypothesis queue"]
    for h in payload.get("hypotheses", []):
        md.append(f"- **{h.get('priority','').upper()} / {h.get('type','')}** — {h.get('reason','')}")

    md += ["", "## Collaboration trace"]
    for wave in payload.get("collaboration_waves", []):
        md.append(f"- Wave {wave.get('wave')}: {len(wave.get('agents', []))} agents; shared evidence packets after wave: {wave.get('shared_evidence_packets_after_wave',0)}")

    (out / "report.md").write_text("\n".join(md), encoding="utf-8")

    finding_rows = []
    for f in reviewed_findings:
        finding_rows.append(
            "<tr>"
            f"<td>{_esc(f.get('title'))}</td><td>{_esc(f.get('target'))}</td>"
            f"<td>{_esc(f.get('status'))}</td><td>{f.get('confidence_score',0)}</td>"
            f"<td>{f.get('independent_agent_count',0)}</td>"
            "</tr>"
        )
    topology_rows = []
    for host, node in topology.items():
        topology_rows.append(
            f"<tr><td>{_esc(host)}</td><td>{node.get('urls',0)}</td>"
            f"<td>{_esc(', '.join(node.get('technologies', [])))}</td>"
            f"<td>{_esc(', '.join(map(str,node.get('status_codes', []))))}</td></tr>"
        )

    html_doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maher Advanced Research Report</title><style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#0b1020;color:#e8edf7;margin:0}}main{{max-width:1200px;margin:auto;padding:32px}}h1,h2{{color:#fff}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{background:#141b2d;border:1px solid #26324d;border-radius:12px;padding:16px}}.n{{font-size:28px;font-weight:700}}table{{width:100%;border-collapse:collapse;background:#11182a}}th,td{{padding:10px;border:1px solid #293653;text-align:left;vertical-align:top}}th{{background:#18223a}}.muted{{color:#aeb9cf}}code{{color:#d7e4ff}}a{{color:#9dc1ff}}
</style></head><body><main><h1>Maher Advanced Vulnerability Research Report</h1><p class="muted">Generated UTC: {_esc(generated)} · Program: {_esc(payload.get('scope',{}).get('program',''))}</p><div class="grid"><div class="card"><div class="n">{payload.get('agent_count',0)}</div>Agents</div><div class="card"><div class="n">{payload.get('hypothesis_count',0)}</div>Hypotheses</div><div class="card"><div class="n">{len(reviewed_findings)}</div>Reviewed candidates</div><div class="card"><div class="n">{sum(1 for x in reviewed_findings if x.get('status')=='validation_priority')}</div>Validation priority</div><div class="card"><div class="n">{counts.get('hosts',0)}</div>Hosts</div><div class="card"><div class="n">{counts.get('endpoints',0)}</div>Endpoints</div></div><h2>Prioritized candidate findings</h2><table><tr><th>Finding</th><th>Target</th><th>Status</th><th>Confidence</th><th>Independent agents</th></tr>{''.join(finding_rows) or '<tr><td colspan="5">No candidate findings yet.</td></tr>'}</table><h2>Architecture topology</h2><table><tr><th>Host</th><th>Observed URLs</th><th>Technologies</th><th>Status codes</th></tr>{''.join(topology_rows) or '<tr><td colspan="4">No HTTP topology collected yet.</td></tr>'}</table><h2>Methodology</h2><p>Hypothesis-driven, collaborative analysis with evidence correlation, contradiction tracking, independent-agent review and explicit validation gates. Scanner output is treated as evidence rather than confirmation.</p></main></body></html>'''
    (out / "report.html").write_text(html_doc, encoding="utf-8")
    return bundle
