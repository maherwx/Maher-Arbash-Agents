from __future__ import annotations

from collections import defaultdict


def summarize_pass(result: dict) -> dict:
    """Create a compact evidence packet that later agents can consume."""
    return {
        "agent": result.get("agent"),
        "status": result.get("status"),
        "observations": (result.get("observations") or [])[:20],
        "candidate_findings": (result.get("candidate_findings") or [])[:20],
        "evidence_notes": (result.get("evidence_notes") or [])[:20],
        "next_checks": (result.get("next_checks") or [])[:20],
    }


def classify_agent(agent: dict) -> str:
    text = " ".join(str(agent.get(k, "")) for k in ("id", "name", "mission", "category")).lower()
    groups = [
        ("discovery", ("recon", "discover", "asset", "surface", "dns", "javascript", "endpoint")),
        ("identity", ("auth", "oauth", "sso", "session", "identity", "account")),
        ("authorization", ("authorization", "idor", "tenant", "role", "permission", "access control")),
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
        packet = summarize_pass(result)
        if packet["candidate_findings"] or packet["observations"] or packet["evidence_notes"]:
            useful.append(packet)
    return useful[-max_packets:]
