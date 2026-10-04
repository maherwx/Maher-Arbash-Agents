from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, asdict


@dataclass(slots=True)
class ProvenanceChain:
    id: str
    start: str
    end: str
    score: float
    hops: list[dict]
    evidence_kinds: list[str]

    def as_dict(self) -> dict:
        return asdict(self)


def _chain_id(start: str, end: str, hops: list[dict]) -> str:
    material = start + "\0" + end + "\0" + "\0".join(
        f"{h.get('from')}|{h.get('relation')}|{h.get('to')}" for h in hops
    )
    return "prov:" + hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()[:20]


def build_provenance_chains(graph: dict, *, max_depth: int = 8, min_confidence: float = 0.55) -> dict:
    nodes = {n.get("id"): n for n in graph.get("nodes", []) if n.get("id")}
    outgoing = defaultdict(list)
    for e in graph.get("edges", []):
        conf = float(e.get("confidence") or 1.0)
        if conf < min_confidence:
            continue
        outgoing[e.get("from")].append(e)

    starts = [
        nid for nid, n in nodes.items()
        if n.get("kind") in {"route", "protocol_signal", "behavioral_anomaly"}
    ]
    terminal_kinds = {
        "code_variable_write", "code_parameter", "code_function",
        "behavioral_anomaly", "hypothesis"
    }

    chains = []
    seen_signatures = set()

    for start in starts:
        q = deque([(start, [], 1.0, {start})])
        while q:
            current, hops, score, visited = q.popleft()
            if len(hops) >= max_depth:
                continue
            for edge in outgoing.get(current, []):
                nxt = edge.get("to")
                if not nxt or nxt in visited:
                    continue
                conf = float(edge.get("confidence") or 1.0)
                new_score = score * conf
                hop = {
                    "from": current,
                    "to": nxt,
                    "relation": edge.get("relation"),
                    "confidence": conf,
                    "symbol": edge.get("symbol"),
                    "provenance": edge.get("provenance"),
                }
                new_hops = hops + [hop]
                node = nodes.get(nxt, {})
                signature = (start, nxt, tuple(h.get("relation") for h in new_hops))
                if node.get("kind") in terminal_kinds and signature not in seen_signatures:
                    seen_signatures.add(signature)
                    kinds = [nodes.get(start, {}).get("kind", "unknown")]
                    kinds.extend(nodes.get(h["to"], {}).get("kind", "unknown") for h in new_hops)
                    chains.append(ProvenanceChain(
                        id=_chain_id(start, nxt, new_hops),
                        start=start,
                        end=nxt,
                        score=round(new_score, 4),
                        hops=new_hops,
                        evidence_kinds=kinds,
                    ).as_dict())
                q.append((nxt, new_hops, new_score, visited | {nxt}))

    chains.sort(key=lambda x: (-x["score"], -len(x["hops"]), x["id"]))
    return {
        "schema_version": "1.0",
        "chain_count": len(chains),
        "chains": chains[:2000],
    }


def summarize_provenance(chains: dict) -> dict:
    by_start = defaultdict(int)
    strong = 0
    for chain in chains.get("chains", []):
        by_start[chain.get("start")] += 1
        if float(chain.get("score") or 0) >= 0.8:
            strong += 1
    return {
        "chain_count": chains.get("chain_count", 0),
        "strong_chain_count": strong,
        "starts_with_chains": len(by_start),
        "top_starts": sorted(
            [{"node": k, "chains": v} for k, v in by_start.items()],
            key=lambda x: (-x["chains"], x["node"])
        )[:50],
    }
