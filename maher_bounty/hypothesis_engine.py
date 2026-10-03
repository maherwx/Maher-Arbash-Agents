from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlparse


def build_hypotheses(inventory: dict) -> list[dict]:
    """Generate evidence-led research hypotheses from normalized recon data.

    This intentionally prioritizes relationships, inconsistencies and application
    structure over simple signature matching. It does not execute requests.
    """
    hypotheses: list[dict] = []
    endpoints = inventory.get("endpoints", [])
    http = inventory.get("http", [])

    parsed = []
    for item in endpoints:
        value = item.get("value", "") if isinstance(item, dict) else str(item)
        try:
            u = urlparse(value)
        except ValueError:
            continue
        if not u.scheme or not u.netloc:
            continue
        params = sorted(k for k, _ in parse_qsl(u.query, keep_blank_values=True))
        parsed.append((value, u, params))

    # Hidden/high-value application surfaces inferred from route semantics.
    route_groups = {
        "identity_access": ("login", "signin", "auth", "oauth", "sso", "session", "account", "profile"),
        "authorization_objects": ("user", "member", "tenant", "org", "team", "project", "invoice", "order", "document", "file"),
        "workflow_state": ("approve", "verify", "confirm", "cancel", "refund", "invite", "reset", "activate", "checkout"),
        "api_graph": ("api", "graphql", "graphiql", "swagger", "openapi", "rpc", "v1", "v2", "v3"),
        "integration_surface": ("webhook", "callback", "redirect", "integration", "import", "export", "upload"),
    }
    for group, needles in route_groups.items():
        matches = [v for v, u, _ in parsed if any(n in u.path.lower() for n in needles)]
        if matches:
            hypotheses.append({
                "type": group,
                "priority": "high" if group in {"identity_access", "authorization_objects", "workflow_state"} else "medium",
                "reason": "Application routes expose a security-sensitive semantic cluster worth relationship and state analysis.",
                "evidence": matches[:30],
                "research_questions": [
                    "Do equivalent objects behave differently across roles, tenants, or workflow states?",
                    "Are server-side decisions consistent when the same operation is reached through alternate routes or API versions?",
                    "Does the application enforce the same invariant before and after state transitions?",
                ],
            })

    # Parameter families: repeated identifiers across unrelated routes often reveal object graphs.
    param_routes: dict[str, set[str]] = defaultdict(set)
    for value, u, params in parsed:
        for p in params:
            param_routes[p].add(u.path)
    for param, routes in sorted(param_routes.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(routes) >= 3:
            hypotheses.append({
                "type": "cross_route_parameter_invariant",
                "priority": "high",
                "reason": f"Parameter '{param}' appears across {len(routes)} distinct routes.",
                "evidence": sorted(routes)[:30],
                "research_questions": [
                    "Does this identifier represent the same object/tenant boundary everywhere?",
                    "Do read and write paths apply equivalent authorization and validation?",
                    "Are legacy and current routes enforcing identical ownership rules?",
                ],
            })

    # API/version drift: compare route families with version tokens removed.
    families: dict[str, set[str]] = defaultdict(set)
    for value, u, _ in parsed:
        parts = [p for p in u.path.split("/") if p]
        normalized = "/" + "/".join("{version}" if p.lower() in {"v1", "v2", "v3", "v4"} else p for p in parts)
        if "{version}" in normalized:
            families[normalized].add(u.path)
    for family, variants in families.items():
        if len(variants) > 1:
            hypotheses.append({
                "type": "api_version_drift",
                "priority": "high",
                "reason": "Multiple API generations expose the same apparent resource family.",
                "evidence": sorted(variants),
                "research_questions": [
                    "Are authentication, authorization, field filtering and workflow rules equivalent across versions?",
                    "Does an older version expose fields or state transitions removed from the newer interface?",
                ],
            })

    # Technology combinations are more useful than isolated fingerprints.
    tech_counter = Counter()
    for row in http:
        for tech in row.get("technologies", []) or []:
            tech_counter[str(tech)] += 1
    if tech_counter:
        hypotheses.append({
            "type": "technology_topology",
            "priority": "medium",
            "reason": "Technology distribution can reveal separate stacks, legacy islands, admin surfaces, and inconsistent gateways.",
            "evidence": [{"technology": k, "hosts": v} for k, v in tech_counter.most_common(20)],
            "research_questions": [
                "Which hosts differ from the dominant stack and why?",
                "Do legacy or uncommon stacks expose alternate authentication or routing behavior?",
            ],
        })

    # Keep deterministic ordering and bounded context.
    rank = {"high": 0, "medium": 1, "low": 2}
    hypotheses.sort(key=lambda x: (rank.get(x.get("priority", "low"), 9), x.get("type", "")))
    return hypotheses[:100]
