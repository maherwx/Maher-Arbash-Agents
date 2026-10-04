from __future__ import annotations

from .differential import compare_responses


def evaluate_pair(test_case: dict, baseline: dict, candidate: dict) -> dict:
    diff = compare_responses(baseline, candidate)
    score = 0
    signals = []

    if diff["status_changed"]:
        score += 20
        signals.append("status changed")
    if diff["body_similarity"] < 0.75:
        score += 35
        signals.append("major semantic/body divergence")
    elif diff["body_similarity"] < 0.92:
        score += 20
        signals.append("moderate body divergence")
    if abs(diff["body_length_delta"]) > 512:
        score += 10
        signals.append("material response size delta")
    if diff["changed_headers"]:
        score += min(15, 3 + len(diff["changed_headers"]))
        signals.append("stable header divergence")

    if test_case.get("type") in {"identity_tenant_differential", "cross_identity_relation"} and diff["material_difference"]:
        score += 20
        signals.append("identity/tenant-sensitive behavior")

    return {
        "test_case": test_case.get("id"),
        "type": test_case.get("type"),
        "priority": test_case.get("priority"),
        "difference": diff,
        "signal_score": min(100, score),
        "signals": signals,
        "needs_validation": score >= 40,
        "needs_independent_recheck": score >= 65,
    }
