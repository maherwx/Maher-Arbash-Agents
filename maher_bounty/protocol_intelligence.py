from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

GRAPHQL_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.I)
WS_RE = re.compile(r"\b(?:wss?|websocket)://[^\s\"'<>]+", re.I)
GRPC_CT = ("application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto")


@dataclass(slots=True, frozen=True)
class ProtocolSignal:
    protocol: str
    source: str
    key: str
    confidence: float
    metadata: dict

    def as_dict(self) -> dict:
        return asdict(self)


def _json(raw: str):
    try:
        return json.loads(raw or "")
    except Exception:
        return None


def _headers(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    text = raw or ""
    parsed = _json(text)
    if isinstance(parsed, dict):
        header_rows = parsed.get("headers")
        if isinstance(header_rows, list):
            for row in header_rows:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or "").strip().lower()
                if name:
                    out[name] = str(row.get("value") or "").strip()
    for line in text.replace("\r\n", "\n").split("\n"):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        if key and key not in {"{", "[", '"headers"'}:
            out[key] = v.strip()
    return out


def _graphql_payload(req: str) -> str:
    parsed = _json(req)
    if isinstance(parsed, dict):
        post = parsed.get("postData")
        if isinstance(post, dict):
            text = post.get("text")
            if isinstance(text, str):
                nested = _json(text)
                if isinstance(nested, dict) and isinstance(nested.get("query"), str):
                    return nested["query"]
                return text
        if isinstance(parsed.get("query"), str):
            return parsed["query"]
    return req


def _openapi_document(raw: str) -> bool:
    parsed = _json(raw)
    candidates = [parsed]
    if isinstance(parsed, dict):
        content = parsed.get("content")
        if isinstance(content, dict) and isinstance(content.get("text"), str):
            candidates.append(_json(content["text"]))
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        if isinstance(obj.get("openapi"), str) and isinstance(obj.get("paths"), dict):
            return True
        if isinstance(obj.get("swagger"), str) and isinstance(obj.get("paths"), dict):
            return True
    return False


def analyze_http_records(records: Iterable[dict]) -> dict:
    signals: list[ProtocolSignal] = []
    graph_ops = Counter(); ws_hosts = Counter(); grpc_routes = Counter(); openapi_hits = Counter()
    for index, record in enumerate(records):
        url = str(record.get("url", "")); req = str(record.get("request_raw", "")); resp = str(record.get("response_raw", "")); source = f"traffic:{index}"
        headers = {**_headers(req), **_headers(resp)}; content_type = headers.get("content-type", "").lower()

        for kind, name in GRAPHQL_RE.findall(_graphql_payload(req)):
            graph_ops[f"{kind.lower()}:{name}"] += 1
            signals.append(ProtocolSignal("graphql", source, name, 0.98, {"operation_type": kind.lower(), "url": url}))

        for candidate in WS_RE.findall(req + "\n" + resp + "\n" + url):
            host = candidate.split("/", 3)[2] if "/" in candidate else candidate
            ws_hosts[host] += 1
            signals.append(ProtocolSignal("websocket", source, candidate, 0.99, {"url": url}))

        if any(ct in content_type for ct in GRPC_CT) or "grpc-status" in headers:
            grpc_routes[url] += 1
            signals.append(ProtocolSignal("grpc", source, url, 0.97, {"content_type": content_type, "grpc_status": headers.get("grpc-status")}))

        if _openapi_document(resp) or _openapi_document(req):
            openapi_hits[url] += 1
            signals.append(ProtocolSignal("openapi", source, url, 0.96, {}))

    by_protocol = Counter(s.protocol for s in signals)
    return {"signal_count":len(signals),"protocol_counts":dict(by_protocol),"graphql_operations":dict(graph_ops),"websocket_hosts":dict(ws_hosts),"grpc_routes":dict(grpc_routes),"openapi_hits":dict(openapi_hits),"signals":[s.as_dict() for s in signals]}


def analyze_source_protocols(root: str | Path, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(root); signals = []
    extensions = {".js",".jsx",".ts",".tsx",".py",".go",".rs",".java",".kt",".cs",".php",".rb",".graphql",".gql",".proto",".yaml",".yml",".json"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in extensions: continue
        if any(p in {".git","node_modules","vendor","target","dist","build",".venv"} for p in path.parts): continue
        try:
            if path.stat().st_size > max_file_bytes: continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError: continue
        rel = str(path.relative_to(root)); low = text.lower()
        if path.suffix.lower()==".proto" or ("service " in low and "rpc " in low): signals.append(ProtocolSignal("grpc-proto",rel,rel,0.99,{}))
        for kind,name in GRAPHQL_RE.findall(text): signals.append(ProtocolSignal("graphql-source",rel,name,0.95,{"operation_type":kind.lower()}))
        for candidate in WS_RE.findall(text): signals.append(ProtocolSignal("websocket-source",rel,candidate,0.98,{}))
        if path.suffix.lower() in {".yaml",".yml",".json"}:
            structured = _json(text) if path.suffix.lower()==".json" else None
            if (isinstance(structured,dict) and (("openapi" in structured and "paths" in structured) or ("swagger" in structured and "paths" in structured))) or (path.suffix.lower() in {".yaml",".yml"} and re.search(r"(?m)^\s*(openapi|swagger)\s*:",text) and re.search(r"(?m)^\s*paths\s*:",text)):
                signals.append(ProtocolSignal("openapi-source",rel,rel,0.9,{}))
    counts=Counter(s.protocol for s in signals)
    return {"signal_count":len(signals),"protocol_counts":dict(counts),"signals":[s.as_dict() for s in signals]}
