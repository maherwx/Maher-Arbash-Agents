from __future__ import annotations

from collections import defaultdict


def capability_quality(results: list[dict]) -> dict:
    """Compute quality by capability instead of hiding weak engines in one global score."""
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for row in results:
        name = str(row.get("name", "unknown"))
        if "graphql" in name:
            capability = "graphql"
        elif "grpc" in name:
            capability = "grpc"
        elif "openapi" in name:
            capability = "openapi"
        elif "websocket" in name:
            capability = "websocket"
        elif "identity" in name or "workflow" in name:
            capability = "workflow_identity"
        else:
            capability = "generic_http"

        expected = bool(row.get("classification", {}).get("expected_signal"))
        observed = bool(row.get("classification", {}).get("observed_signal"))
        key = "tp" if expected and observed else "fn" if expected else "fp" if observed else "tn"
        buckets[capability][key] += 1

    out = {}
    for capability, counts in sorted(buckets.items()):
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        out[capability] = {
            **counts,
            "precision": round(tp / max(1, tp + fp), 4),
            "recall": round(tp / max(1, tp + fn), 4),
            "specificity": round(tn / max(1, tn + fp), 4),
            "false_positive_rate": round(fp / max(1, fp + tn), 4),
        }
    return out


def quality_gate(summary: dict, *, min_precision: float = 0.80, min_recall: float = 0.80, max_fpr: float = 0.20) -> dict:
    quality = summary.get("quality", {})
    checks = {
        "precision": float(quality.get("precision", 0.0)) >= min_precision,
        "recall": float(quality.get("recall", 0.0)) >= min_recall,
        "false_positive_rate": float(quality.get("false_positive_rate", 1.0)) <= max_fpr,
        "all_cases_pass": int(summary.get("failed", 1)) == 0,
    }
    return {"passed": all(checks.values()), "checks": checks, "thresholds": {"min_precision": min_precision, "min_recall": min_recall, "max_fpr": max_fpr}}
