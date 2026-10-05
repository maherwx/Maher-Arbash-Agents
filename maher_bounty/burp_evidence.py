from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from .scope_policy import filter_in_scope_urls


_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "x-auth-token", "x-csrf-token",
}
MAX_TRAFFIC_EVIDENCE_RECORDS = 500


def _header_names(raw: str) -> list[str]:
    names = set()
    for line in str(raw or "").replace("\r\n", "\n").split("\n"):
        if not line:
            break
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lower()
        if name and name not in _SENSITIVE_HEADERS:
            names.add(name)
    return sorted(names)


def build_scoped_traffic_evidence(records: list[dict], scope: dict) -> dict:
    """Summarize Burp/HAR traffic for agents without exposing headers or bodies."""
    summaries = []
    rejected = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        url = str(record.get("url") or "")
        allowed, _ = filter_in_scope_urls([url], scope)
        if not allowed:
            rejected += 1
            continue
        parsed = urlparse(url)
        request = str(record.get("request_raw") or "")
        response = str(record.get("response_raw") or "")
        summaries.append({
            "source": str(record.get("source") or "traffic"),
            "url": url,
            "method": str(record.get("method") or "GET").upper(),
            "status": record.get("status"),
            "query_parameter_names": sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}),
            "request_header_names": _header_names(request),
            "response_header_names": _header_names(response),
            "request_body_present": bool(request and ("\r\n\r\n" in request or "\n\n" in request)),
            "response_body_present": bool(response and ("\r\n\r\n" in response or "\n\n" in response)),
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
