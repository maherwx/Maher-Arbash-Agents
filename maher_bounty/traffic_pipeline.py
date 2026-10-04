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
from .persistence import ResearchStore


def analyze_traffic(path: str | Path, *, kind: str = "auto", out_dir: str | Path = "results/traffic-analysis", db_path: str | Path = ".maher/research.db") -> dict:
    source = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = ingest_traffic(source, kind)
    canonical = canonicalize_many(records)
    behavior = build_behavior_model(records)
    anomalies = cluster_transactions(canonical)
    protocols = analyze_http_records(records)
    workflow = build_workflow_model(records)
    workflow_divergences = compare_identity_workflows(workflow)
    test_matrix = build_advanced_test_matrix(canonical)

    result = {
        "schema_version": "2.0",
        "source_file": str(source),
        "source_kind": kind,
        "record_count": len(records),
        "canonical_count": len(canonical),
        "behavior": behavior,
        "anomalies": anomalies,
        "protocols": protocols,
        "workflow": workflow,
        "workflow_divergences": workflow_divergences,
        "test_matrix": test_matrix,
    }

    artifacts = {
        "canonical-http.json": canonical,
        "behavior-model.json": behavior,
        "anomalies.json": anomalies,
        "protocol-intelligence.json": protocols,
        "workflow-model.json": workflow,
        "workflow-divergences.json": workflow_divergences,
        "test-matrix.json": test_matrix,
        "summary.json": result,
    }
    for filename, payload in artifacts.items():
        (out / filename).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    store = ResearchStore(db_path)
    run_id = store.create_run({"program": "traffic-analysis-v2", "source": str(source)})
    try:
        store.checkpoint(run_id, "traffic_ingest", {"count": len(records), "source": str(source)})
        store.checkpoint(run_id, "canonical_http", canonical)
        store.checkpoint(run_id, "behavior_model", behavior)
        store.checkpoint(run_id, "anomaly_clusters", anomalies)
        store.checkpoint(run_id, "protocol_intelligence", protocols)
        store.checkpoint(run_id, "workflow_model", workflow)
        store.checkpoint(run_id, "workflow_divergences", workflow_divergences)
        store.checkpoint(run_id, "advanced_test_matrix", test_matrix)
        for idx, item in enumerate(anomalies.get("anomalies", [])):
            store.add_evidence(run_id, f"traffic-anomaly:{idx}", "behavioral_anomaly", item)
        for idx, item in enumerate(workflow_divergences.get("divergences", [])):
            store.add_evidence(run_id, f"workflow-divergence:{idx}", "workflow_divergence", item)
        for idx, item in enumerate(protocols.get("signals", [])):
            store.add_evidence(run_id, f"protocol-signal:{idx}", "protocol_signal", item)
        store.finish(run_id)
    except Exception:
        store.finish(run_id, "failed")
        raise

    result["run_id"] = run_id
    return result
