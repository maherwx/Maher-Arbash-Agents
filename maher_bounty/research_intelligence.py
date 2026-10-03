from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def architecture_map(inventory: dict) -> dict:
    """Build a compact application topology from collected evidence."""
    hosts = defaultdict(lambda: {"urls": 0, "technologies": set(), "status_codes": set(), "titles": set()})
    for row in inventory.get("http", []) or []:
        url = row.get("url") or ""
        host = urlparse(url).netloc if url else ""
        if not host:
            continue
        node = hosts[host]
        node["urls"] += 1
        node["technologies"].update(str(x) for x in (row.get("technologies") or []))
        if row.get("status_code") is not None:
            node["status_codes"].add(row.get("status_code"))
        if row.get("title"):
            node["titles"].add(str(row.get("title")))
    return {
        host: {
            "urls": data["urls"],
            "technologies": sorted(data["technologies"]),
            "status_codes": sorted(data["status_codes"], key=str),
            "titles": sorted(data["titles"])[:10],
        }
        for host, data in sorted(hosts.items())
    }


def review_findings(results: list[dict]) -> list[dict]:
    """Normalize candidates and rank research attention by evidence quality and impact signals.

    This is a triage quality gate, not an exploitation engine. A candidate is never
    marked confirmed merely because an agent or scanner emitted it.
    """
    merged: dict[str, dict] = {}
    for result in results:
        agent = result.get("agent")
        for raw in result.get("candidate_findings") or []:
            if isinstance(raw, str):
                item = {"title": raw}
            elif isinstance(raw, dict):
                item = dict(raw)
            else:
                continue
            title = str(item.get("title") or item.get("name") or "untitled candidate").strip()
            target = str(item.get("target") or item.get("url") or item.get("endpoint") or "").strip()
            key = (title.lower() + "|" + target.lower())
            record = merged.setdefault(key, {
                "title": title,
                "target": target,
                "reported_by": [],
                "evidence": [],
                "impact_signals": [],
                "contradictions": [],
                "status": "candidate",
            })
            if agent and agent not in record["reported_by"]:
                record["reported_by"].append(agent)
            evidence = item.get("evidence") or item.get("evidence_notes") or []
            if isinstance(evidence, str):
                evidence = [evidence]
            record["evidence"].extend(str(x) for x in evidence if x)
            impact = item.get("impact") or item.get("impact_signals") or []
            if isinstance(impact, str):
                impact = [impact]
            record["impact_signals"].extend(str(x) for x in impact if x)
            contradiction = item.get("contradictions") or []
            if isinstance(contradiction, str):
                contradiction = [contradiction]
            record["contradictions"].extend(str(x) for x in contradiction if x)

    reviewed = []
    for record in merged.values():
        independent_sources = len(record["reported_by"])
        evidence_count = len(set(record["evidence"]))
        impact_count = len(set(record["impact_signals"]))
        contradiction_count = len(set(record["contradictions"]))
        score = min(100, independent_sources * 12 + evidence_count * 8 + impact_count * 10 - contradiction_count * 12)
        record["confidence_score"] = max(0, score)
        record["independent_agent_count"] = independent_sources
        record["evidence"] = list(dict.fromkeys(record["evidence"]))[:30]
        record["impact_signals"] = list(dict.fromkeys(record["impact_signals"]))[:20]
        record["contradictions"] = list(dict.fromkeys(record["contradictions"]))[:20]
        if independent_sources >= 2 and evidence_count >= 2 and contradiction_count == 0:
            record["status"] = "validation_priority"
        elif contradiction_count:
            record["status"] = "needs_conflict_resolution"
        reviewed.append(record)

    reviewed.sort(key=lambda x: (-x["confidence_score"], -len(x["impact_signals"]), x["title"].lower()))
    return reviewed


def research_directives() -> dict:
    return {
        "strategy": "depth_over_noise",
        "directives": [
            "Model the application as identities, objects, trust boundaries, state transitions, integrations and data flows.",
            "Ask what invariant the server intends to enforce, then compare that invariant across roles, tenants, routes, versions and workflow states.",
            "Prefer differential analysis and contradictory behavior over generic payload spraying.",
            "Use passive and collected evidence to identify uncommon surfaces, legacy islands, alternate stacks and hidden relationships.",
            "Promote a candidate only when multiple independent observations support the same security consequence.",
            "Separate technical anomaly from demonstrated security impact; record both explicitly.",
            "Challenge high-impact candidates with a dedicated false-positive hypothesis before reporting them.",
            "Preserve reproducible evidence, affected object relationships, prerequisites and expected-versus-observed behavior.",
        ],
    }
