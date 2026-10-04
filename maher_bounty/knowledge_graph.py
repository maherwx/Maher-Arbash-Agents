from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def build_application_graph(inventory: dict, hypotheses: list[dict] | None = None) -> dict:
    """Build a relationship graph for application structure and research evidence."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, kind: str, **attrs):
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, **attrs})

    for host in inventory.get("hosts", []) or []:
        value = host.get("value", "") if isinstance(host, dict) else str(host)
        if value:
            add_node(f"host:{value}", "host", value=value)

    route_counts = defaultdict(int)
    for endpoint in inventory.get("endpoints", []) or []:
        value = endpoint.get("value", "") if isinstance(endpoint, dict) else str(endpoint)
        try:
            u = urlparse(value)
        except ValueError:
            continue
        if not u.netloc:
            continue
        host_id = f"host:{u.netloc}"
        route_id = f"route:{u.netloc}{u.path}"
        add_node(host_id, "host", value=u.netloc)
        add_node(route_id, "route", host=u.netloc, path=u.path)
        edges.append({"from": host_id, "to": route_id, "relation": "exposes"})
        route_counts[route_id] += 1

    for idx, hypothesis in enumerate(hypotheses or []):
        hid = f"hypothesis:{idx}"
        add_node(hid, "hypothesis", type=hypothesis.get("type"), priority=hypothesis.get("priority"), reason=hypothesis.get("reason"))
        for evidence in hypothesis.get("evidence", [])[:30]:
            if isinstance(evidence, str):
                for node_id, node in nodes.items():
                    if node.get("kind") == "route" and evidence in node.get("path", ""):
                        edges.append({"from": hid, "to": node_id, "relation": "supported_by"})

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "hosts": sum(1 for n in nodes.values() if n["kind"] == "host"),
            "routes": sum(1 for n in nodes.values() if n["kind"] == "route"),
            "hypotheses": sum(1 for n in nodes.values() if n["kind"] == "hypothesis"),
        },
    }
