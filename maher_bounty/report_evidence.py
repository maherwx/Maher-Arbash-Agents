from __future__ import annotations


def build_evidence_report(*, priorities: dict | None = None, provenance: dict | None = None,
                          anomalies: dict | None = None, workflow_divergences: dict | None = None) -> dict:
    priority_map = {str(x.get("key")): x for x in (priorities or {}).get("targets", [])}
    chains = list((provenance or {}).get("chains", []))

    items = []
    for chain in chains:
        start = str(chain.get("start"))
        matching_priority = priority_map.get(start)
        items.append({
            "title": f"Evidence chain {chain.get('id')}",
            "start": start,
            "end": chain.get("end"),
            "confidence": chain.get("score"),
            "priority_score": matching_priority.get("score") if matching_priority else None,
            "priority_reasons": matching_priority.get("reasons", []) if matching_priority else [],
            "evidence_kinds": chain.get("evidence_kinds", []),
            "steps": chain.get("hops", []),
        })

    items.sort(key=lambda x: (
        -(float(x.get("priority_score") or 0)),
        -(float(x.get("confidence") or 0)),
        x.get("title") or ""
    ))

    return {
        "schema_version": "1.0",
        "item_count": len(items),
        "items": items[:1000],
        "summary": {
            "anomaly_count": (anomalies or {}).get("anomaly_count", 0),
            "workflow_divergence_count": (workflow_divergences or {}).get("divergence_count", 0),
            "provenance_chain_count": (provenance or {}).get("chain_count", 0),
            "priority_target_count": (priorities or {}).get("target_count", 0),
        },
    }
