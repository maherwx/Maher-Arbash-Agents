from __future__ import annotations

from collections import defaultdict


def build_advanced_test_matrix(transactions: list[dict], session_matrix: list[dict] | None = None) -> dict:
    """
    Build high-value differential research cases from observed application behavior.

    The planner does not spray generic payloads. It derives comparisons from real
    route families, identities, tenants, methods, statuses and versioned paths.
    """
    session_matrix = session_matrix or []
    route_groups = defaultdict(list)
    for tx in transactions:
        key = (
            tx.get("host"),
            tx.get("route_shape"),
            tuple(tx.get("query_keys") or []),
        )
        route_groups[key].append(tx)

    cases = []
    case_id = 0

    for (host, route_shape, query_keys), rows in route_groups.items():
        methods = sorted({r.get("method") for r in rows if r.get("method")})
        statuses = sorted({r.get("status") for r in rows if r.get("status") is not None})
        identities = sorted({r.get("identity") for r in rows if r.get("identity")})
        tenants = sorted({r.get("tenant") for r in rows if r.get("tenant")})

        if len(methods) > 1:
            case_id += 1
            cases.append({
                "id": f"T{case_id:05d}",
                "type": "method_invariant",
                "priority": "high",
                "host": host,
                "route_shape": route_shape,
                "query_keys": list(query_keys),
                "observed_methods": methods,
                "research_goal": "Compare equivalent resource behavior across supported methods and verify consistent server-side invariants.",
                "expected_evidence": ["status", "response structure", "object visibility", "state transition"],
            })

        if len(statuses) > 1:
            case_id += 1
            cases.append({
                "id": f"T{case_id:05d}",
                "type": "status_divergence",
                "priority": "high",
                "host": host,
                "route_shape": route_shape,
                "query_keys": list(query_keys),
                "observed_statuses": statuses,
                "research_goal": "Explain why structurally equivalent observations produce different authorization or workflow outcomes.",
                "expected_evidence": ["identity context", "tenant context", "request fingerprint", "response fingerprint"],
            })

        if len(identities) > 1 or len(tenants) > 1:
            case_id += 1
            cases.append({
                "id": f"T{case_id:05d}",
                "type": "identity_tenant_differential",
                "priority": "critical",
                "host": host,
                "route_shape": route_shape,
                "identities": identities,
                "tenants": tenants,
                "research_goal": "Compare object and action visibility across identities/tenants for inconsistent authorization or isolation behavior.",
                "expected_evidence": ["same-object comparison", "role/tenant mapping", "expected-vs-observed behavior"],
            })

    for relation in session_matrix:
        if relation.get("source") == relation.get("target"):
            continue
        case_id += 1
        cases.append({
            "id": f"T{case_id:05d}",
            "type": "cross_identity_relation",
            "priority": "high" if not relation.get("same_tenant") else "medium",
            "source_identity": relation.get("source"),
            "target_identity": relation.get("target"),
            "source_role": relation.get("source_role"),
            "target_role": relation.get("target_role"),
            "source_tenant": relation.get("source_tenant"),
            "target_tenant": relation.get("target_tenant"),
            "research_goal": "Use paired identities to validate server-side ownership, role, and tenant boundaries on equivalent operations.",
            "expected_evidence": ["paired requests", "paired responses", "object ownership context"],
        })

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cases.sort(key=lambda x: (rank.get(x.get("priority", "low"), 9), x["id"]))

    return {
        "case_count": len(cases),
        "critical": sum(1 for x in cases if x.get("priority") == "critical"),
        "high": sum(1 for x in cases if x.get("priority") == "high"),
        "cases": cases[:1000],
    }
