from __future__ import annotations

import math
from dataclasses import dataclass, asdict


@dataclass(slots=True)
class PriorityScore:
    key: str
    score: float
    confidence: float
    reasons: list[str]
    evidence: dict

    def as_dict(self) -> dict:
        return asdict(self)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def rank_analysis_targets(*, anomalies: dict | None = None, workflow_divergences: dict | None = None,
                          protocols: dict | None = None, source_correlations: dict | None = None,
                          database: dict | None = None, dataflow_graph: dict | None = None) -> dict:
    """Fuse independent evidence sources into explainable review priorities."""
    buckets: dict[str, dict] = {}

    def bucket(key: str) -> dict:
        return buckets.setdefault(key, {"score": 0.0, "confidence_parts": [], "reasons": [], "evidence": {}})

    for item in (anomalies or {}).get("anomalies", []):
        key = str(item.get("route_shape") or item.get("host") or "unknown")
        b = bucket(key); raw = float(item.get("anomaly_score") or 0)
        b["score"] += min(30.0, raw * 0.30)
        b["confidence_parts"].append(min(1.0, 0.45 + float(item.get("observations") or 0) / 20.0))
        b["reasons"].append("behavioral divergence"); b["evidence"]["anomaly"] = item

    for item in (workflow_divergences or {}).get("divergences", []):
        key = str(item.get("target") or item.get("source") or "unknown")
        b = bucket(key); contexts = len(item.get("contexts", []))
        b["score"] += min(30.0, 18.0 + contexts * 3.0)
        b["confidence_parts"].append(min(1.0, 0.55 + contexts * 0.08))
        b["reasons"].append("identity/tenant workflow divergence"); b["evidence"]["workflow"] = item

    for item in (protocols or {}).get("signals", []):
        meta = item.get("metadata") or {}; key = str(meta.get("url") or item.get("key") or "unknown")
        b = bucket(key); protocol = str(item.get("protocol") or "unknown")
        b["score"] += {"graphql": 8, "grpc": 8, "websocket": 7, "openapi": 4}.get(protocol, 3)
        b["confidence_parts"].append(float(item.get("confidence") or 0.5)); b["reasons"].append(f"{protocol} surface")
        b["evidence"].setdefault("protocols", []).append(item)

    for item in (source_correlations or {}).get("correlations", []):
        key = str(item.get("route") or item.get("file") or "unknown"); b = bucket(key); sinks = item.get("sinks") or {}
        b["score"] += min(28.0, 12.0 + (8.0 if "sql" in sinks else 0.0) + (8.0 if "process" in sinks else 0.0))
        b["confidence_parts"].append(0.85 if item.get("runtime_observations") else 0.6)
        b["reasons"].append("source-to-runtime dataflow correlation"); b["evidence"]["source_runtime"] = item

    for item in (database or {}).get("raw_query_sites", []):
        key = str(item.get("file") or "database"); b = bucket(key); b["score"] += 5.0; b["confidence_parts"].append(0.7)
        b["reasons"].append("raw database query construction"); b["evidence"].setdefault("database_sites", []).append(item)

    graph = dataflow_graph or {}
    node_index = {n.get("id"): n for n in graph.get("nodes", [])}
    for entrypoint, reached in graph.get("reachable_from_routes", {}).items():
        fn = node_index.get(entrypoint, {}); bindings = fn.get("route_bindings") or []
        key = str((bindings[0].get("path") if bindings else None) or fn.get("name") or entrypoint)
        qualified = [x for x in reached if float(x.get("confidence") or 0) >= 0.7]
        if not qualified:
            continue
        b = bucket(key); depth = max((int(x.get("depth") or 0) for x in qualified), default=0)
        argument_edges = sum(1 for x in qualified if x.get("via") == "argument_flow")
        b["score"] += min(24.0, 6.0 + len(qualified) * 0.8 + argument_edges * 2.0 + depth)
        b["confidence_parts"].append(min(0.96, 0.65 + argument_edges * 0.05 + min(depth, 5) * 0.03))
        b["reasons"].append("interprocedural route-reachable dataflow")
        b["evidence"]["interprocedural_dataflow"] = {"entrypoint": entrypoint, "reachable": qualified[:100]}

    ranked = []
    for key, data in buckets.items():
        parts = data["confidence_parts"]
        confidence = 1.0 - math.prod(1.0 - _clamp(x, 0.0, 1.0) for x in parts) if parts else 0.0
        score = _clamp(data["score"] * (0.65 + 0.35 * confidence))
        ranked.append(PriorityScore(key, round(score, 2), round(confidence, 4), sorted(set(data["reasons"])), data["evidence"]).as_dict())

    ranked.sort(key=lambda x: (-x["score"], -x["confidence"], x["key"]))
    return {"target_count": len(ranked), "targets": ranked}
