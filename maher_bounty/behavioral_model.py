from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlparse

TOKEN_RE = re.compile(r"\b(?:[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Za-z0-9_-]{24,}|\d{5,})\b", re.I)
PATH_ID_RE = re.compile(r"/(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})(?=/|$)", re.I)


def _stable_text(text: str) -> str:
    text = TOKEN_RE.sub("{token}", text or "")
    return re.sub(r"\s+", " ", text).strip()


def _route_shape(url: str) -> str:
    u = urlparse(url)
    path = PATH_ID_RE.sub("/{id}", u.path or "/")
    keys = sorted(k for k, _ in parse_qsl(u.query, keep_blank_values=True))
    return f"{u.netloc}{path}?{'&'.join(keys)}" if keys else f"{u.netloc}{path}"


def fingerprint(record: dict) -> dict:
    request = _stable_text(record.get("request_raw", ""))
    response = _stable_text(record.get("response_raw", ""))
    shape = _route_shape(record.get("url", ""))
    material = json.dumps({
        "shape": shape,
        "method": record.get("method"),
        "status": record.get("status"),
        "request": request[:20000],
        "response": response[:50000],
    }, sort_keys=True, ensure_ascii=False)
    return {
        "route_shape": shape,
        "behavior_sha256": hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest(),
        "request_size": len(request),
        "response_size": len(response),
    }


def build_behavior_model(records: list[dict]) -> dict:
    groups = defaultdict(list)
    methods = Counter()
    statuses = Counter()
    for record in records:
        fp = fingerprint(record)
        enriched = {**record, **fp}
        groups[fp["route_shape"]].append(enriched)
        methods[record.get("method", "UNKNOWN")] += 1
        statuses[str(record.get("status"))] += 1

    families = []
    for shape, items in groups.items():
        unique_behaviors = {x["behavior_sha256"] for x in items}
        families.append({
            "route_shape": shape,
            "observations": len(items),
            "unique_behaviors": len(unique_behaviors),
            "methods": sorted({x.get("method") for x in items if x.get("method")}),
            "statuses": sorted({x.get("status") for x in items if x.get("status") is not None}),
            "behavior_variance": round(len(unique_behaviors) / max(1, len(items)), 4),
        })

    families.sort(key=lambda x: (-x["behavior_variance"], -x["observations"], x["route_shape"]))
    return {
        "record_count": len(records),
        "route_family_count": len(families),
        "methods": dict(methods),
        "statuses": dict(statuses),
        "families": families,
    }
