from __future__ import annotations

import hashlib
import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .scope_policy import filter_in_scope_urls


_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "x-auth-token", "x-csrf-token",
}
MAX_TRAFFIC_EVIDENCE_RECORDS = 500


def _header_names(raw: str) -> list[str]:
    value = str(raw or "")
    names = set()
    if value.lstrip().startswith("{"):
        try:
            message = json.loads(value)
        except json.JSONDecodeError:
            message = {}
        headers = message.get("headers", []) if isinstance(message, dict) else []
        for header in headers:
            name = str(header.get("name") or "").strip().lower() if isinstance(header, dict) else ""
            if name and name not in _SENSITIVE_HEADERS:
                names.add(name)
        return sorted(names)
    for line in value.replace("\r\n", "\n").split("\n"):
        if not line:
            break
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lower()
        if name and name not in _SENSITIVE_HEADERS:
            names.add(name)
    return sorted(names)


def _body_present(raw: str) -> bool:
    value = str(raw or "")
    if value.lstrip().startswith("{"):
        try:
            message = json.loads(value)
        except json.JSONDecodeError:
            message = {}
        post_data = message.get("postData") if isinstance(message, dict) else None
        return bool(isinstance(post_data, dict) and (post_data.get("text") or post_data.get("params")))
    return "\r\n\r\n" in value or "\n\n" in value


def _target_ref(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname + (f":{parsed.port}" if parsed.port else "")
    safe_query = urlencode([(name, "[redacted]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, safe_query, ""))


def build_traffic_target_references(records: list[dict], scope: dict) -> dict[str, str]:
    """Keep exact approved URLs in the local coordinator, outside model context."""
    mapping = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        url = str(record.get("url") or "")
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            continue
        allowed, _ = filter_in_scope_urls([url], scope)
        if allowed:
            mapping[_target_ref(url)] = url
    return mapping


def build_scoped_traffic_evidence(records: list[dict], scope: dict) -> dict:
    """Summarize scoped Burp/HAR traffic without query, header, or body values."""
    summaries = []
    rejected = 0
    references = build_traffic_target_references(records, scope)
    for record in records:
        if not isinstance(record, dict):
            continue
        url = str(record.get("url") or "")
        allowed, _ = filter_in_scope_urls([url], scope)
        if not allowed:
            rejected += 1
            continue
        reference = _target_ref(url)
        if reference not in references:
            rejected += 1
            continue
        parsed = urlparse(url)
        request = str(record.get("request_raw") or "")
        response = str(record.get("response_raw") or "")
        summaries.append({
            "source": str(record.get("source") or "traffic"),
            "url": _safe_url(url),
            "target_ref": reference,
            "method": str(record.get("method") or "GET").upper(),
            "status": record.get("status"),
            "query_parameter_names": sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}),
            "request_header_names": _header_names(request),
            "response_header_names": _header_names(response),
            "request_body_present": _body_present(request),
            "response_body_present": _body_present(response),
        })
        if len(summaries) >= MAX_TRAFFIC_EVIDENCE_RECORDS:
            break
    return {
        "source": "burp_or_har_import",
        "records": summaries,
        "record_count": len(summaries),
        "out_of_scope_records_filtered": rejected,
        "truncated": len(summaries) >= MAX_TRAFFIC_EVIDENCE_RECORDS,
    }
