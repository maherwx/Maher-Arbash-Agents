from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlsplit


_SENSITIVE_NAME = re.compile(r"(token|secret|password|passwd|session|authorization|cookie|api[_-]?key)", re.I)
_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f-]{27,}$")
_OPAQUE = re.compile(r"(?i)^(?:[a-f0-9]{24,}|[a-z0-9_-]{32,})$")


def _safe_host(parsed) -> str:
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return host.lower() + (f":{port}" if port and port != default_port else "")


def _route(record: dict) -> str:
    parsed = urlsplit(str(record.get("url") or ""))
    host = _safe_host(parsed)
    parts = []
    for segment in (parsed.path or "/").split("/"):
        if not segment:
            continue
        if _SENSITIVE_NAME.search(segment) or _OPAQUE.match(segment):
            segment = "{sensitive}"
        elif segment.isdigit():
            segment = "{int}"
        elif _UUID.match(segment):
            segment = "{uuid}"
        parts.append(segment)
    return (host + "/" + "/".join(parts)).rstrip("/") or host + "/"


def _http_parts(raw: str, kind: str) -> tuple[dict[str, str], str, int | None]:
    headers: dict[str, str] = {}
    body = ""
    status = None
    if not raw:
        return headers, body, status
    try:
        obj = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        obj = None
    if isinstance(obj, dict):
        source = obj.get("request" if kind == "request" else "response", obj)
        if isinstance(source, dict):
            for item in source.get("headers", []) or []:
                if isinstance(item, dict) and item.get("name"):
                    name = str(item["name"]).lower()
                    headers[name] = str(item.get("value") or "")
            if kind == "response":
                try:
                    status = int(source.get("status"))
                except (TypeError, ValueError):
                    pass
                content = source.get("content") or {}
                body = str(content.get("text") or "") if isinstance(content, dict) else ""
            else:
                post = source.get("postData") or {}
                body = str(post.get("text") or "") if isinstance(post, dict) else ""
        return headers, body, status

    boundary = re.search(r"\r?\n\r?\n", raw)
    head = raw[:boundary.start()] if boundary else raw
    body = raw[boundary.end():] if boundary else ""
    lines = head.splitlines()
    if kind == "response" and lines:
        match = re.match(r"HTTP/\S+\s+(\d{3})", lines[0])
        if match:
            status = int(match.group(1))
    for line in lines[1:] if kind == "response" else lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return headers, body, status


def _safe_param_names(record: dict, request_headers: dict[str, str], request_body: str) -> list[str]:
    parsed = urlsplit(str(record.get("url") or ""))
    names = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    content_type = request_headers.get("content-type", "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        names.update(key for key, _ in parse_qsl(request_body, keep_blank_values=True))
    elif "json" in content_type:
        try:
            data = json.loads(request_body)
        except (TypeError, json.JSONDecodeError):
            data = None
        def walk(value, prefix="", depth=0):
            if depth > 6:
                return
            if isinstance(value, dict):
                for key, child in list(value.items())[:100]:
                    name = str(key)
                    joined = f"{prefix}.{name}" if prefix else name
                    names.add(joined)
                    walk(child, joined, depth + 1)
            elif isinstance(value, list):
                for child in value[:30]:
                    walk(child, prefix + "[]" if prefix else "[]", depth + 1)
        walk(data)
    return sorted(name for name in names if name and not _SENSITIVE_NAME.search(name))


def _body_shape(body: str) -> str:
    if not body:
        return "empty"
    try:
        parsed = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return f"text:{min(len(body) // 256, 20)}"
    paths: list[str] = []
    def walk(value, prefix="", depth=0):
        if depth > 6 or len(paths) >= 40:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:40]:
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, path, depth + 1)
                else:
                    paths.append(path + ":" + type(child).__name__)
        elif isinstance(value, list):
            if value:
                walk(value[0], prefix + "[]", depth + 1)
            else:
                paths.append(prefix + "[]:empty")
    walk(parsed)
    return "json:" + ",".join(sorted(paths))


def _response_signature(record: dict) -> tuple:
    headers, body, status = _http_parts(str(record.get("response_raw") or ""), "response")
    status = record.get("status") if record.get("status") is not None else status
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    return status, _body_shape(body), min(len(body) // 256, 20), headers.get("content-type", "").split(";", 1)[0].lower()


def map_request_surface(records: list[dict]) -> dict:
    families = defaultdict(list)
    for record in records[:20000]:
        route = _route(record)
        if route and route != "/":
            req_headers, req_body, _ = _http_parts(str(record.get("request_raw") or ""), "request")
            families[(route, str(record.get("method") or "GET").upper())].append(
                (record, _safe_param_names(record, req_headers, req_body))
            )
    rows = []
    for (route, method), samples in sorted(families.items()):
        rows.append({
            "route_family": route,
            "method": method,
            "observed_requests": len(samples),
            "status_codes": sorted({str(row.get("status")) for row, _ in samples if row.get("status") is not None}),
            "parameter_names": sorted({name for _, names in samples for name in names}),
            "sources": sorted({str(row.get("source") or "unknown") for row, _ in samples}),
        })
    return {"tool": "request_surface_mapper", "route_family_count": len(rows), "routes": rows[:5000]}


def compare_auth_boundaries(records: list[dict]) -> dict:
    grouped = defaultdict(lambda: defaultdict(set))
    for record in records[:20000]:
        req_headers, _, _ = _http_parts(str(record.get("request_raw") or ""), "request")
        auth_state = "credential_present" if any(
            req_headers.get(name) for name in ("authorization", "cookie", "x-api-key", "x-auth-token")
        ) else "no_credential_observed"
        grouped[(_route(record), str(record.get("method") or "GET").upper())][auth_state].add(_response_signature(record))
    candidates = []
    for (route, method), states in sorted(grouped.items()):
        if len(states) < 2:
            continue
        if states.get("credential_present") and states.get("no_credential_observed") and states["credential_present"] != states["no_credential_observed"]:
            candidates.append({
                "route_family": route, "method": method,
                "credential_response_signatures": len(states["credential_present"]),
                "no_credential_response_signatures": len(states["no_credential_observed"]),
                "status": "manual_review",
                "reason": "observed response behavior differs between credential-present and no-credential requests",
            })
    return {"tool": "auth_boundary_differential", "candidate_count": len(candidates), "candidates": candidates[:2000]}


def audit_response_posture(records: list[dict]) -> dict:
    expected = ("content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy")
    host_rows = defaultdict(lambda: {"https": False, "requests": 0, "header_presence": Counter(), "signals": []})
    for record in records[:20000]:
        parsed = urlsplit(str(record.get("url") or ""))
        host = _safe_host(parsed)
        if not host:
            continue
        headers, _, _ = _http_parts(str(record.get("response_raw") or ""), "response")
        # Some HAR exports have a response object but no raw header block.
        host_rows[host]["https"] |= parsed.scheme.lower() == "https"
        host_rows[host]["requests"] += 1
        for name in headers:
            host_rows[host]["header_presence"][name] += 1
        origin = headers.get("access-control-allow-origin", "").strip()
        credentials = headers.get("access-control-allow-credentials", "").strip().lower()
        if origin == "*" and credentials == "true":
            host_rows[host]["signals"].append("wildcard_cors_with_credentials")
        for cookie in headers.get("set-cookie", "").splitlines():
            parts = [part.strip().lower() for part in cookie.split(";")]
            cookie_name = cookie.split("=", 1)[0].strip()
            attributes = set(parts[1:])
            secure = "secure" in attributes
            httponly = "httponly" in attributes
            same_site_none = any(part.replace(" ", "") == "samesite=none" for part in attributes)
            if cookie_name and not secure:
                host_rows[host]["signals"].append("cookie_missing_secure")
            if cookie_name and not httponly:
                host_rows[host]["signals"].append("cookie_missing_httponly")
            if same_site_none and not secure:
                host_rows[host]["signals"].append("samesite_none_without_secure")
    results = []
    for host, data in sorted(host_rows.items()):
        missing = [name for name in expected if data["header_presence"][name] == 0]
        if data["https"] and data["header_presence"]["strict-transport-security"] == 0:
            missing.append("strict-transport-security")
        results.append({
            "host": host, "observed_responses": data["requests"],
            "missing_security_headers": missing,
            "signals": sorted(set(data["signals"])),
            "status": "passive_review",
        })
    return {"tool": "response_security_posture", "host_count": len(results), "hosts": results}


def correlate_parameter_behavior(records: list[dict]) -> dict:
    grouped = defaultdict(set)
    for record in records[:20000]:
        req_headers, req_body, _ = _http_parts(str(record.get("request_raw") or ""), "request")
        signature = _response_signature(record)
        for name in _safe_param_names(record, req_headers, req_body):
            grouped[(_route(record), str(record.get("method") or "GET").upper(), name)].add(signature)
    signals = []
    for (route, method, name), signatures in sorted(grouped.items()):
        if len(signatures) > 1:
            signals.append({
                "route_family": route, "method": method, "parameter_name": name,
                "distinct_observed_response_shapes": len(signatures),
                "status": "manual_review",
                "reason": "responses vary across captured requests containing this parameter; causality is not established",
            })
    return {"tool": "parameter_behavior_correlator", "signal_count": len(signals), "signals": signals[:3000]}


def model_workflow_transitions(records: list[dict]) -> dict:
    grouped = defaultdict(list)
    for index, record in enumerate(records[:20000]):
        identity = str(record.get("identity") or "")
        req_headers, _, _ = _http_parts(str(record.get("request_raw") or ""), "request")
        # Keep identity material in memory only; publish stable run-local actor labels.
        actor_key = identity if identity else ("authenticated" if any(req_headers.get(k) for k in ("authorization", "cookie", "x-api-key")) else "anonymous")
        sequence = record.get("sequence", index)
        try:
            sequence = float(sequence)
        except (TypeError, ValueError):
            sequence = float(index)
        grouped[actor_key].append((sequence, record))
    edges = Counter()
    states = set()
    for actor_records in grouped.values():
        ordered = sorted(actor_records, key=lambda item: item[0])
        labels = []
        for _, record in ordered:
            label = f"{str(record.get('method') or 'GET').upper()} {_route(record)} -> {record.get('status') or 'unknown'}"
            labels.append(label)
            states.add(label)
        edges.update(zip(labels, labels[1:]))
    transitions = [
        {"from": source, "to": target, "observed_count": count}
        for (source, target), count in sorted(edges.items())
    ]
    return {
        "tool": "workflow_transition_miner", "state_count": len(states),
        "transition_count": len(transitions), "transitions": transitions[:5000],
    }


def run_advanced_web_tools(records: list[dict]) -> dict:
    return {
        "request_surface": map_request_surface(records),
        "auth_boundary": compare_auth_boundaries(records),
        "response_posture": audit_response_posture(records),
        "parameter_behavior": correlate_parameter_behavior(records),
        "workflow_transitions": model_workflow_transitions(records),
    }
