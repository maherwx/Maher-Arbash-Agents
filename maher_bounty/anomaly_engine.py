from __future__ import annotations

from collections import defaultdict


def cluster_transactions(transactions: list[dict]) -> dict:
    groups = defaultdict(list)
    for tx in transactions:
        key = (tx.get("host"), tx.get("method"), tx.get("route_shape"), tuple(tx.get("query_keys") or []))
        groups[key].append(tx)

    anomalies = []
    for key, rows in groups.items():
        if len(rows) < 2:
            continue
        statuses = {r.get("status") for r in rows}
        bodies = {r.get("response_body_sha256") for r in rows}
        sizes = [int(r.get("response_size") or 0) for r in rows]
        identities = {r.get("identity") for r in rows if r.get("identity")}
        tenants = {r.get("tenant") for r in rows if r.get("tenant")}
        spread = max(sizes) - min(sizes) if sizes else 0
        score = 0
        reasons = []
        if len(statuses) > 1:
            score += 25; reasons.append("status divergence")
        if len(bodies) > 1:
            score += 30; reasons.append("response body divergence")
        if spread > 256:
            score += min(20, 5 + spread // 4096); reasons.append("response size divergence")
        if len(identities) > 1:
            score += 15; reasons.append("multi-identity observations")
        if len(tenants) > 1:
            score += 15; reasons.append("multi-tenant observations")
        if score:
            anomalies.append({
                "host": key[0], "method": key[1], "route_shape": key[2], "query_keys": list(key[3]),
                "observations": len(rows), "statuses": sorted(x for x in statuses if x is not None),
                "unique_response_bodies": len(bodies), "response_size_spread": spread,
                "identities": sorted(identities), "tenants": sorted(tenants),
                "anomaly_score": min(100, score), "reasons": reasons,
            })
    anomalies.sort(key=lambda x: (-x["anomaly_score"], -x["observations"], x["route_shape"]))
    return {"group_count": len(groups), "anomaly_count": len(anomalies), "anomalies": anomalies}
