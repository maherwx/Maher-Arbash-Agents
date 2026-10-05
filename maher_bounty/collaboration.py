from __future__ import annotations

from collections import defaultdict


def summarize_pass(result: dict) -> dict:
    """Create a compact evidence packet that later agents can consume."""
    def items(field):
        value = result.get(field)
        if not isinstance(value, list):
            return []
        return [item for item in value[:20] if isinstance(item, (str, dict))]

    return {
        "agent": result.get("agent"),
        "status": result.get("status"),
        "observations": items("observations"),
        "candidate_findings": [item for item in items("candidate_findings") if isinstance(item, dict)],
        "evidence_notes": items("evidence_notes"),
        "next_checks": items("next_checks"),
    }


def classify_agent(agent: dict) -> str:
    text = " ".join(str(agent.get(k, "")) for k in ("id", "name", "mission", "category")).lower()
    groups = [
        ("discovery", ("recon", "discover", "asset", "surface", "dns", "javascript", "endpoint")),
        ("authorization", ("authorization", "idor", "tenant", "role", "permission", "access control")),
        ("identity", ("auth", "oauth", "sso", "session", "identity", "account")),
        ("api_workflow", ("api", "graphql", "business", "workflow", "logic", "state", "race")),
        ("validation", ("valid", "triage", "verify", "evidence", "false positive")),
        ("reporting", ("report", "write", "severity", "impact")),
    ]
    for group, needles in groups:
        if any(n in text for n in needles):
            return group
    return "specialist"


def build_waves(agents: list[dict]) -> list[list[dict]]:
    """Order specialists so later waves can reason over earlier evidence."""
    order = ["discovery", "identity", "authorization", "api_workflow", "specialist", "validation", "reporting"]
    buckets: dict[str, list[dict]] = defaultdict(list)
    for agent in agents:
        buckets[classify_agent(agent)].append(agent)
    return [buckets[g] for g in order if buckets[g]]


def evidence_bus(results: list[dict], max_packets: int = 80) -> list[dict]:
    """Shared research memory. No requests are executed here."""
    useful = []
    for result in results:
        if not isinstance(result, dict):
            continue
        packet = summarize_pass(result)
        if packet["candidate_findings"] or packet["observations"] or packet["evidence_notes"]:
            useful.append(packet)
    return useful[-max_packets:]
