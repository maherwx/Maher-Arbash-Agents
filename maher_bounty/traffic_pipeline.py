from __future__ import annotations

import json
from pathlib import Path

from .traffic_ingest import ingest_traffic
from .http_model import canonicalize_many
from .behavioral_model import build_behavior_model
from .anomaly_engine import cluster_transactions
from .persistence import ResearchStore


def analyze_traffic(path: str | Path, *, kind: str = "auto", out_dir: str | Path = "results/traffic-analysis", db_path: str | Path = ".maher/research.db") -> dict:
    source = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = ingest_traffic(source, kind)
    canonical = canonicalize_many(records)
    behavior = build_behavior_model(records)
    anomalies = cluster_transactions(canonical)

    result = {
        "schema_version": "1.0",
        "source_file": str(source),
        "source_kind": kind,
        "record_count": len(records),
        "canonical_count": len(canonical),
        "behavior": behavior,
        "anomalies": anomalies,
    }

    (out / "canonical-http.json").write_text(json.dumps(canonical, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "behavior-model.json").write_text(json.dumps(behavior, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "anomalies.json").write_text(json.dumps(anomalies, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    store = ResearchStore(db_path)
    run_id = store.create_run({"program": "traffic-analysis", "source": str(source)})
    try:
        store.checkpoint(run_id, "traffic_ingest", {"count": len(records), "source": str(source)})
        store.checkpoint(run_id, "canonical_http", canonical)
        store.checkpoint(run_id, "behavior_model", behavior)
        store.checkpoint(run_id, "anomaly_clusters", anomalies)
        for idx, item in enumerate(anomalies.get("anomalies", [])):
            store.add_evidence(run_id, f"traffic-anomaly:{idx}", "behavioral_anomaly", item)
        store.finish(run_id)
    except Exception:
        store.finish(run_id, "failed")
        raise

    result["run_id"] = run_id
    return result
