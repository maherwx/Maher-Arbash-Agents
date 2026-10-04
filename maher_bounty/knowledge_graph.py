from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from urllib.parse import urlparse


def _id(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{kind}:{digest}"


def build_application_graph(
    inventory: dict,
    hypotheses: list[dict] | None = None,
    *,
    protocol_intelligence: dict | None = None,
    behavior_model: dict | None = None,
    anomalies: dict | None = None,
) -> dict:
    """Build a typed evidence graph spanning assets, routes, protocols and behavioral observations."""
    nodes: dict[str, dict] = {}
    edge_keys: set[tuple[str, str, str]] = set()
    edges: list[dict] = []

    def add_node(node_id: str, kind: str, **attrs) -> str:
        current = nodes.setdefault(node_id, {"id": node_id, "kind": kind})
        for key, value in attrs.items():
            if value not in (None, "", [], {}):
                current[key] = value
        return node_id

    def add_edge(src: str, dst: str, relation: str, **attrs) -> None:
        key = (src, dst, relation)
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"from": src, "to": dst, "relation": relation, **attrs})

    host_lookup: dict[str, str] = {}
    route_lookup: dict[tuple[str, str], str] = {}

    for host in inventory.get("hosts", []) or []:
        value = host.get("value", "") if isinstance(host, dict) else str(host)
        if value:
            host_lookup[value] = add_node(_id("host", value), "host", value=value)

    for endpoint in inventory.get("endpoints", []) or []:
        value = endpoint.get("value", "") if isinstance(endpoint, dict) else str(endpoint)
        try:
            u = urlparse(value)
        except ValueError:
            continue
        if not u.netloc:
            continue
        host_id = host_lookup.setdefault(u.netloc, add_node(_id("host", u.netloc), "host", value=u.netloc))
        route_key = (u.netloc, u.path or "/")
        route_id = route_lookup.setdefault(route_key, add_node(_id("route", f"{u.netloc}{u.path or '/'}"), "route", host=u.netloc, path=u.path or "/"))
        add_edge(host_id, route_id, "exposes")

    for family in (behavior_model or {}).get("families", []) or []:
        shape = str(family.get("route_shape", ""))
        if not shape:
            continue
        node_id = add_node(_id("behavior", shape), "behavior_family", route_shape=shape,
                           observations=family.get("observations"), variance=family.get("behavior_variance"),
                           methods=family.get("methods"), statuses=family.get("statuses"))
        for (host, path), route_id in route_lookup.items():
            if path in shape or shape.endswith(path):
                add_edge(route_id, node_id, "has_behavior")

    for signal in (protocol_intelligence or {}).get("signals", []) or []:
        protocol = str(signal.get("protocol", "unknown")); key = str(signal.get("key", ""))
        if not key:
            continue
        pid = add_node(_id("protocol", f"{protocol}:{key}"), "protocol_signal", protocol=protocol,
                       key=key, confidence=signal.get("confidence"), metadata=signal.get("metadata", {}), source=signal.get("source"))
        metadata = signal.get("metadata") or {}
        url = str(metadata.get("url", key if key.startswith(("http://", "https://", "ws://", "wss://")) else ""))
        if url:
            u = urlparse(url)
            if u.netloc:
                hid = host_lookup.setdefault(u.netloc, add_node(_id("host", u.netloc), "host", value=u.netloc))
                add_edge(hid, pid, "speaks")
                rid = route_lookup.get((u.netloc, u.path or "/"))
                if rid:
                    add_edge(rid, pid, "uses_protocol")

    for index, anomaly in enumerate((anomalies or {}).get("anomalies", []) or []):
        stable = f"{anomaly.get('host')}:{anomaly.get('method')}:{anomaly.get('route_shape')}:{index}"
        aid = add_node(_id("anomaly", stable), "behavioral_anomaly", score=anomaly.get("anomaly_score"),
                       reasons=anomaly.get("reasons", []), observations=anomaly.get("observations"))
        host = str(anomaly.get("host", "")); shape = str(anomaly.get("route_shape", ""))
        if host:
            hid = host_lookup.setdefault(host, add_node(_id("host", host), "host", value=host))
            add_edge(hid, aid, "has_anomaly")
        for (route_host, path), rid in route_lookup.items():
            if route_host == host and (path in shape or shape.endswith(path)):
                add_edge(rid, aid, "exhibits")

    for index, hypothesis in enumerate(hypotheses or []):
        stable = f"{hypothesis.get('type')}:{hypothesis.get('reason')}:{index}"
        hid = add_node(_id("hypothesis", stable), "hypothesis", type=hypothesis.get("type"),
                       priority=hypothesis.get("priority"), reason=hypothesis.get("reason"))
        for evidence in hypothesis.get("evidence", [])[:100]:
            text = str(evidence)
            for node_id, node in list(nodes.items()):
                if node.get("kind") == "route" and text and text in str(node.get("path", "")):
                    add_edge(hid, node_id, "supported_by")

    adjacency = defaultdict(set)
    for edge in edges:
        adjacency[edge["from"]].add(edge["to"]); adjacency[edge["to"]].add(edge["from"])

    components = []
    unseen = set(nodes)
    while unseen:
        start = unseen.pop(); q = deque([start]); component = {start}
        while q:
            cur = q.popleft()
            for nxt in adjacency[cur]:
                if nxt in unseen:
                    unseen.remove(nxt); component.add(nxt); q.append(nxt)
        components.append(component)

    degree = Counter()
    for edge in edges:
        degree[edge["from"]] += 1; degree[edge["to"]] += 1
    hubs = [{"id": node_id, "degree": deg, "kind": nodes[node_id]["kind"]} for node_id, deg in degree.most_common(25)]
    kind_counts = Counter(node["kind"] for node in nodes.values())

    return {
        "schema_version": "2.0",
        "nodes": list(nodes.values()), "edges": edges,
        "stats": {"nodes": len(nodes), "edges": len(edges), "components": len(components), "kinds": dict(kind_counts)},
        "hubs": hubs,
        "components": [{"size": len(c), "node_ids": sorted(c)} for c in sorted(components, key=len, reverse=True)[:50]],
    }
