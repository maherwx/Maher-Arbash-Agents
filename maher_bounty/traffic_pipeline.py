from __future__ import annotations

import json
from pathlib import Path

from .traffic_ingest import ingest_traffic
from .http_model import canonicalize_many
from .behavioral_model import build_behavior_model
from .anomaly_engine import cluster_transactions
from .protocol_intelligence import analyze_http_records
from .workflow_intelligence import build_workflow_model, compare_identity_workflows
from .test_matrix import build_advanced_test_matrix
from .adaptive_prioritizer import rank_analysis_targets
from .knowledge_graph import build_application_graph
from .provenance_engine import build_provenance_chains, summarize_provenance
from .report_evidence import build_evidence_report
from .correlation_engine import correlate_evidence
from .persistence import ResearchStore
from .advanced_web_tools import run_advanced_web_tools


def _inventory_from_records(records: list[dict]) -> dict:
    hosts = {}
    endpoints = {}
    for record in records:
        url = str(record.get("url") or "")
        if not url:
            continue
        from urllib.parse import urlparse
        u = urlparse(url)
        if u.netloc:
            hosts[u.netloc] = {"value": u.netloc}
            endpoints[url] = {"value": url}
    return {"hosts": list(hosts.values()), "endpoints": list(endpoints.values())}


def analyze_traffic(path: str | Path, *, kind: str = "auto", out_dir: str | Path = "results/traffic-analysis", db_path: str | Path = ".maher/research.db") -> dict:
    source = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = ingest_traffic(source, kind)
    canonical = canonicalize_many(records)
    behavior = build_behavior_model(records)
    anomalies = cluster_transactions(canonical)
    protocols = analyze_http_records(records)
    advanced_tools = run_advanced_web_tools(records)
    workflow = build_workflow_model(records)
    workflow_divergences = compare_identity_workflows(workflow)
    test_matrix = build_advanced_test_matrix(canonical)
    priorities = rank_analysis_targets(anomalies=anomalies, workflow_divergences=workflow_divergences, protocols=protocols)

    inventory = _inventory_from_records(records)
    graph = build_application_graph(inventory, protocol_intelligence=protocols, behavior_model=behavior, anomalies=anomalies)
    provenance = build_provenance_chains(graph)
    provenance_summary = summarize_provenance(provenance)
    evidence_report = build_evidence_report(priorities=priorities, provenance=provenance, anomalies=anomalies, workflow_divergences=workflow_divergences)

    # Correlation is intentionally conservative. The pipeline exposes the current
    # traffic source now; callers can add replay/source-analysis evidence later.
    correlations = correlate_evidence({"source": "traffic", "signals": protocols.get("signals", [])})

    result = {
        "schema_version": "2.3", "source_file": str(source), "source_kind": kind,
        "record_count": len(records), "canonical_count": len(canonical),
        "behavior": behavior, "anomalies": anomalies, "protocols": protocols,
        "advanced_web_tools": advanced_tools,
        "workflow": workflow, "workflow_divergences": workflow_divergences,
        "test_matrix": test_matrix, "priorities": priorities, "knowledge_graph": graph,
        "provenance": provenance, "provenance_summary": provenance_summary,
        "evidence_report": evidence_report, "correlations": correlations,
    }

    artifacts = {
        "canonical-http.json": canonical, "behavior-model.json": behavior, "anomalies.json": anomalies,
        "protocol-intelligence.json": protocols, "advanced-web-tools.json": advanced_tools,
        "workflow-model.json": workflow,
        "workflow-divergences.json": workflow_divergences, "test-matrix.json": test_matrix,
        "priorities.json": priorities, "knowledge-graph.json": graph, "provenance-chains.json": provenance,
        "provenance-summary.json": provenance_summary, "evidence-report.json": evidence_report,
        "correlations.json": correlations, "summary.json": result,
    }
    for filename, payload in artifacts.items():
        (out / filename).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    store = ResearchStore(db_path)
    run_id = store.create_run({"program": "traffic-analysis-v2.3", "source": str(source)})
    try:
        store.checkpoint(run_id, "traffic_ingest", {"count": len(records), "source": str(source)})
        store.checkpoint(run_id, "canonical_http", canonical)
        store.checkpoint(run_id, "behavior_model", behavior)
        store.checkpoint(run_id, "anomaly_clusters", anomalies)
        store.checkpoint(run_id, "protocol_intelligence", protocols)
        store.checkpoint(run_id, "advanced_web_tools", advanced_tools)
        store.checkpoint(run_id, "workflow_model", workflow)
        store.checkpoint(run_id, "workflow_divergences", workflow_divergences)
        store.checkpoint(run_id, "advanced_test_matrix", test_matrix)
        store.checkpoint(run_id, "adaptive_priorities", priorities)
        store.checkpoint(run_id, "knowledge_graph", graph)
        store.checkpoint(run_id, "provenance_chains", provenance)
        store.checkpoint(run_id, "evidence_report", evidence_report)
        store.checkpoint(run_id, "evidence_correlations", correlations)
        for idx, item in enumerate(anomalies.get("anomalies", [])): store.add_evidence(run_id, f"traffic-anomaly:{idx}", "behavioral_anomaly", item)
        for idx, item in enumerate(workflow_divergences.get("divergences", [])): store.add_evidence(run_id, f"workflow-divergence:{idx}", "workflow_divergence", item)
        for idx, item in enumerate(protocols.get("signals", [])): store.add_evidence(run_id, f"protocol-signal:{idx}", "protocol_signal", item)
        for idx, item in enumerate(priorities.get("targets", [])[:100]): store.add_evidence(run_id, f"priority-target:{idx}", "adaptive_priority", item)
        for idx, item in enumerate(provenance.get("chains", [])[:200]): store.add_evidence(run_id, f"provenance-chain:{idx}", "evidence_provenance", item)
        for idx, item in enumerate(correlations.get("correlations", [])[:200]): store.add_evidence(run_id, f"correlation:{idx}", "evidence_correlation", item)
        store.finish(run_id)
    except Exception:
        store.finish(run_id, "failed")
        raise

    result["run_id"] = run_id
    return result
