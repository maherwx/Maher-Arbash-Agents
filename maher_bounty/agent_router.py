from __future__ import annotations

from collections import defaultdict

ALWAYS_GROUPS = {"validation", "reporting"}


def _text(agent: dict) -> str:
    return " ".join(str(agent.get(k, "")) for k in ("id", "name", "mission", "category")).lower()


def _signals(context: dict) -> set[str]:
    values = set()
    inventory = context.get("inventory", {}) or {}
    for row in inventory.get("http", []) or []:
        values.update(str(x).lower() for x in row.get("technologies", []) or [])
        values.add(str(row.get("title") or "").lower())
    for endpoint in inventory.get("endpoints", []) or []:
        value = endpoint.get("value", "") if isinstance(endpoint, dict) else str(endpoint)
        values.add(value.lower())
    for item in (context.get("validated_evidence", {}) or {}).get("items", []) or []:
        values.add(str(item.get("kind") or "").lower())
        values.add(str(item.get("title") or "").lower())
    return values


def _score(agent: dict, signals: set[str]) -> float:
    text = _text(agent)
    score = 0.0
    mappings = {
        "graphql": ("graphql",),
        "oauth": ("oauth", "oidc"),
        "sso": ("sso", "saml"),
        "websocket": ("websocket", "ws://", "wss://"),
        "api": ("/api/", "/v1/", "/v2/", "openapi", "swagger"),
        "upload": ("upload", "multipart"),
        "mobile": ("android", "ios", "mobile"),
        "cloud": ("aws", "azure", "gcp", "s3"),
        "auth": ("login", "auth", "session", "token"),
        "tenant": ("tenant", "workspace", "organization"),
        "race": ("race", "concurrent"),
        "payment": ("payment", "checkout", "billing"),
    }
    for agent_key, needles in mappings.items():
        if agent_key in text and any(any(n in signal for n in needles) for signal in signals):
            score += 3.0
    if any(x in text for x in ("evidence", "triage", "false_positive", "report", "impact", "severity")):
        score += 1.5
    if any(x in text for x in ("scope", "authorization", "out_of_scope")):
        score += 2.0
    return score


def route_agents(agents: list[dict], context: dict, *, max_specialists: int = 48, full_sweep: bool = False) -> dict:
    if full_sweep:
        return {"selected": agents, "deferred": [], "reason": "full_sweep", "signals": []}

    signals = _signals(context)
    ranked = sorted((( _score(agent, signals), agent) for agent in agents), key=lambda x: (-x[0], str(x[1].get("id"))))
    mandatory = []
    specialists = []
    deferred = []

    for score, agent in ranked:
        text = _text(agent)
        if any(x in text for x in ("scope", "authorization", "evidence", "triage", "false_positive", "report", "impact", "severity")):
            mandatory.append(agent)
        elif score > 0 and len(specialists) < max_specialists:
            specialists.append(agent)
        else:
            deferred.append(agent)

    selected_by_id = {}
    for agent in mandatory + specialists:
        selected_by_id[str(agent.get("id"))] = agent

    # Sparse targets still get broad discovery/API specialists rather than collapsing to only governance agents.
    if len(selected_by_id) < 20:
        for _, agent in ranked:
            text = _text(agent)
            if any(x in text for x in ("recon", "inventory", "endpoint", "api", "web", "workflow", "auth")):
                selected_by_id.setdefault(str(agent.get("id")), agent)
            if len(selected_by_id) >= 30:
                break

    selected = list(selected_by_id.values())
    selected_ids = {str(x.get("id")) for x in selected}
    deferred = [x for x in agents if str(x.get("id")) not in selected_ids]
    return {
        "selected": selected,
        "deferred": deferred,
        "reason": "evidence_aware",
        "signals": sorted(x for x in signals if x)[:200],
        "selected_count": len(selected),
        "deferred_count": len(deferred),
    }
