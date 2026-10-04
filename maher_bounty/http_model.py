from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlsplit

SENSITIVE = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
VOLATILE = {"date", "age", "x-request-id", "traceparent", "tracestate", "cf-ray", "server-timing"}
ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})$", re.I)

@dataclass(slots=True)
class CanonicalHTTPTransaction:
    source: str
    method: str
    scheme: str
    host: str
    path: str
    route_shape: str
    query_keys: tuple[str, ...]
    status: int | None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body_sha256: str = ""
    response_body_sha256: str = ""
    response_size: int = 0
    identity: str | None = None
    tenant: str | None = None

    def as_dict(self) -> dict:
        data = asdict(self)
        data["query_keys"] = list(self.query_keys)
        return data


def _headers(raw: str) -> dict[str, str]:
    head = (raw or "").split("\r\n\r\n", 1)[0]
    lines = head.replace("\r\n", "\n").split("\n")[1:]
    out = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        if key in SENSITIVE or key in VOLATILE:
            continue
        out[key] = v.strip()
    return out


def _body(raw: str) -> str:
    raw = raw or ""
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)[1]
    if "\n\n" in raw:
        return raw.split("\n\n", 1)[1]
    return ""


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def _shape(path: str) -> str:
    parts = []
    for p in (path or "/").split("/"):
        parts.append("{id}" if ID_SEGMENT.match(p) else p)
    return "/".join(parts) or "/"


def canonicalize(record: dict, *, identity: str | None = None, tenant: str | None = None) -> CanonicalHTTPTransaction:
    u = urlsplit(record.get("url", ""))
    req_raw = record.get("request_raw", "") or ""
    resp_raw = record.get("response_raw", "") or ""
    query_keys = tuple(sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)}))
    return CanonicalHTTPTransaction(
        source=str(record.get("source", "unknown")), method=str(record.get("method", "GET")).upper(),
        scheme=u.scheme, host=u.netloc.lower(), path=u.path or "/", route_shape=_shape(u.path or "/"),
        query_keys=query_keys, status=record.get("status"), request_headers=_headers(req_raw),
        response_headers=_headers(resp_raw), request_body_sha256=_sha(_body(req_raw)),
        response_body_sha256=_sha(_body(resp_raw)), response_size=len(_body(resp_raw).encode("utf-8", errors="ignore")),
        identity=identity, tenant=tenant,
    )


def canonicalize_many(records: list[dict]) -> list[dict]:
    return [canonicalize(r).as_dict() for r in records]


def transaction_fingerprint(tx: dict) -> str:
    material = {k: tx.get(k) for k in ("method", "host", "route_shape", "query_keys", "status", "request_body_sha256", "response_body_sha256")}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
