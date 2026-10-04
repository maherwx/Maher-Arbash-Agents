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
                          database: dict | None = None) -> dict:
    """Fuse independent evidence sources into explainable review priorities."""
    buckets: dict[str, dict] = {}

    def bucket(key: str) -> dict:
        return buckets.setdefault(key, {"score": 0.0, "confidence_parts": [], "reasons": [], "evidence": {}})

    for item in (anomalies or {}).get("anomalies", []):
        key = str(item.get("route_shape") or item.get("host") or "unknown")
        b = bucket(key)
        raw = float(item.get("anomaly_score") or 0)
        b["score"] += min(30.0, raw * 0.30)
        b["confidence_parts"].append(min(1.0, 0.45 + float(item.get("observations") or 0) / 20.0))
        b["reasons"].append("behavioral divergence")
        b["evidence"]["anomaly"] = item

    for item in (workflow_divergences or {}).get("divergences", []):
        key = str(item.get("target") or item.get("source") or "unknown")
        b = bucket(key)
        contexts = len(item.get("contexts", []))
        b["score"] += min(30.0, 18.0 + contexts * 3.0)
        b["confidence_parts"].append(min(1.0, 0.55 + contexts * 0.08))
        b["reasons"].append("identity/tenant workflow divergence")
        b["evidence"]["workflow"] = item

    for item in (protocols or {}).get("signals", []):
        meta = item.get("metadata") or {}
        key = str(meta.get("url") or item.get("key") or "unknown")
        b = bucket(key)
        protocol = str(item.get("protocol") or "unknown")
        weight = {"graphql": 8, "grpc": 8, "websocket": 7, "openapi": 4}.get(protocol, 3)
        b["score"] += weight
        b["confidence_parts"].append(float(item.get("confidence") or 0.5))
        b["reasons"].append(f"{protocol} surface")
        b["evidence"].setdefault("protocols", []).append(item)

    for item in (source_correlations or {}).get("correlations", []):
        key = str(item.get("route") or item.get("file") or "unknown")
        b = bucket(key)
        sinks = item.get("sinks") or {}
        weight = 12.0 + (8.0 if "sql" in sinks else 0.0) + (8.0 if "process" in sinks else 0.0)
        b["score"] += min(28.0, weight)
        b["confidence_parts"].append(0.85 if item.get("runtime_observations") else 0.6)
        b["reasons"].append("source-to-runtime dataflow correlation")
        b["evidence"]["source_runtime"] = item

    raw_sites = (database or {}).get("raw_query_sites", [])
    for item in raw_sites:
        key = str(item.get("file") or "database")
        b = bucket(key)
        b["score"] += 5.0
        b["confidence_parts"].append(0.7)
        b["reasons"].append("raw database query construction")
        b["evidence"].setdefault("database_sites", []).append(item)

    ranked = []
    for key, data in buckets.items():
        parts = data["confidence_parts"]
        confidence = 1.0 - math.prod(1.0 - _clamp(x, 0.0, 1.0) for x in parts) if parts else 0.0
        score = _clamp(data["score"] * (0.65 + 0.35 * confidence))
        ranked.append(PriorityScore(key, round(score, 2), round(confidence, 4), sorted(set(data["reasons"])), data["evidence"]).as_dict())

    ranked.sort(key=lambda x: (-x["score"], -x["confidence"], x["key"]))
    return {"target_count": len(ranked), "targets": ranked}
