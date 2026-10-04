from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

MARKERS = ("/api/", "/graphql", "/graphiql", "/swagger", "/openapi", "/rpc/", "/rest/")


def analyze_api_surface(inventory: dict) -> dict:
    api_routes = []
    versions = defaultdict(set)
    hosts = defaultdict(int)
    for item in inventory.get("endpoints", []) or []:
        value = item.get("value", "") if isinstance(item, dict) else str(item)
        low = value.lower()
        if not any(m in low for m in MARKERS) and not any(f"/v{i}/" in low for i in range(1, 10)):
            continue
        api_routes.append(value)
        try:
            u = urlparse(value)
        except ValueError:
            continue
        hosts[u.netloc] += 1
        parts = [p.lower() for p in u.path.split("/") if p]
        for p in parts:
            if len(p) >= 2 and p[0] == "v" and p[1:].isdigit():
                normalized = "/" + "/".join("{version}" if x == p else x for x in parts)
                versions[normalized].add(p)
    return {
        "route_count": len(set(api_routes)),
        "routes": sorted(set(api_routes))[:1000],
        "hosts": dict(sorted(hosts.items(), key=lambda kv: kv[1], reverse=True)),
        "version_families": [
            {"family": k, "versions": sorted(v)} for k, v in versions.items() if len(v) > 1
        ],
        "schema_hints": [u for u in sorted(set(api_routes)) if any(x in u.lower() for x in ("swagger", "openapi", "graphql", "graphiql"))][:200],
    }
