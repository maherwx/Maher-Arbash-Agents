from __future__ import annotations

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from .json_numbers import finite_json_float


class TrafficInputError(ValueError):
    """An explicit traffic input cannot be read or parsed."""


MAX_TRAFFIC_BYTES = 64 * 1024 * 1024
MAX_TRAFFIC_RECORDS = 10000


def _read_export(path: str | Path) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_TRAFFIC_BYTES + 1)
    if len(data) > MAX_TRAFFIC_BYTES:
        raise TrafficInputError("Traffic export exceeds 64 MiB; split it into smaller exports")
    return data


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("HAR contains duplicate JSON fields")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("HAR contains non-finite JSON values")


def _validate_har_message(message):
    if not isinstance(message, dict):
        raise ValueError("HAR request and response must be objects")
    for field in ("headers", "cookies"):
        rows = message.get(field, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("HAR headers and cookies must be lists of objects")


def _decode(value: str | None, encoded: bool = False) -> str:
    if not value:
        return ""
    if encoded:
        try:
            return base64.b64decode(value).decode("utf-8", errors="replace")
        except Exception:
            return value
    return value


def _record(url: str, method: str = "GET", status: int | None = None, request: str = "", response: str = "", source: str = "unknown", **context) -> dict:
    u = urlparse(url)
    return {
        "source": source,
        "url": url,
        "host": u.netloc,
        "path": u.path or "/",
        "method": method.upper(),
        "status": status,
        "request_raw": _redact_headers(request),
        "response_raw": _redact_headers(response),
        **{k:v for k,v in context.items() if v is not None},
    }


def _redact_headers(raw: str) -> str:
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token"}
    if raw.lstrip().startswith("{"):
        try:
            message = json.loads(raw)
            for row in message.get("headers", []):
                if str(row.get("name", "")).strip().lower() in sensitive:
                    row["value"] = "[redacted]"
            for row in message.get("cookies", []):
                row["value"] = "[redacted]"
            return json.dumps(message, ensure_ascii=False)
        except (ValueError, AttributeError, TypeError):
            return raw
    boundary = re.search(r"\r?\n\r?\n", raw)
    head = raw[:boundary.start()] if boundary else raw
    tail = raw[boundary.start():] if boundary else ""
    lines = []
    redact_continuation = False
    for line in head.splitlines(keepends=True):
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "\r" if line.endswith("\r") else ""
        content = line.rstrip("\r\n")
        if content.startswith((" ", "\t")):
            lines.append(" [redacted]" + ending if redact_continuation else line)
            continue
        name, separator, value = content.partition(":")
        redact_continuation = bool(separator and name.strip().lower() in sensitive)
        lines.append(name + ": [redacted]" + ending if redact_continuation else line)
    return "".join(lines) + tail


def _har_headers(req: dict) -> dict[str,str]:
    return _identity_header_map((str(x.get("name") or ""), str(x.get("value") or ""))
                                for x in req.get("headers", []) if x.get("name"))


def _identity_header_map(pairs) -> dict[str, str]:
    headers = {}
    identity_names = {"authorization", "cookie", "x-user-id", "x-identity", "x-session-id"}
    for name, value in pairs:
        name = name.strip().lower()
        if name in identity_names and name in headers:
            # Duplicate credential/identity headers have server-dependent
            # semantics. Do not assign an actor using an arbitrary last value.
            return {}
        headers[name] = value.strip()
    return headers


def _stable_identity(value: str | None) -> str | None:
    if not value:
        return None
    return "actor-" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _identity_from_headers(headers: dict[str, str]) -> str | None:
    explicit = headers.get("x-user-id") or headers.get("x-identity") or headers.get("x-session-id")
    if explicit:
        return _stable_identity(explicit)
    cookie = headers.get("cookie", "")
    session_cookie = re.compile(
        r"(?:^|;\s*)(?:__Host-)?(?:session(?:id|[_-]?id)?|sid|jsessionid|phpsessid|asp\.net_sessionid|laravel_session|connect\.sid|rack\.session)=([^;]+)",
        re.I,
    )
    matches = session_cookie.findall(cookie)
    if len(matches) > 1:
        return None
    if matches:
        return _stable_identity(matches[0])
    authorization = headers.get("authorization", "")
    return _stable_identity(authorization) if authorization else None


def _har_identity(req: dict) -> str | None:
    return _identity_from_headers(_har_headers(req))


def _burp_identity(raw: str) -> str | None:
    value = str(raw or "")
    boundary = re.search(r"\r?\n\r?\n", value)
    head = value[:boundary.start()] if boundary else value
    pairs = []
    for line in head.splitlines()[1:]:
        if line.startswith((" ", "\t")):
            if pairs:
                name, item = pairs[-1]
                pairs[-1] = (name, item + " " + line.strip())
            continue
        if ":" in line:
            name, item = line.split(":", 1)
            pairs.append((name, item))
    return _identity_from_headers(_identity_header_map(pairs))
def load_har(path: str | Path) -> list[dict]:
    data = json.loads(_read_export(path).decode("utf-8-sig"),
                      object_pairs_hook=_unique_fields, parse_constant=_invalid_constant,
                      parse_float=finite_json_float)
    if not isinstance(data, dict) or not isinstance(data.get("log"), dict) or not isinstance(data["log"].get("entries"), list):
        raise ValueError("HAR requires log.entries")
    if len(data["log"]["entries"]) > MAX_TRAFFIC_RECORDS:
        raise TrafficInputError("Traffic export exceeds 10000 records; split it into smaller exports")
    out = []
    for sequence,entry in enumerate(data.get("log", {}).get("entries", [])):
        if not isinstance(entry, dict):
            raise ValueError("HAR entries must be objects")
        req, resp = entry.get("request", {}), entry.get("response", {})
        _validate_har_message(req)
        _validate_har_message(resp)
        if not isinstance(req.get("url", ""), str) or not isinstance(req.get("method", "GET"), str):
            raise ValueError("HAR URL and method must be strings")
        out.append(_record(
            req.get("url", ""), req.get("method", "GET"), resp.get("status"),
            json.dumps(req, ensure_ascii=False), json.dumps(resp, ensure_ascii=False), "har",
            timestamp=entry.get("startedDateTime"), sequence=sequence, identity=_har_identity(req),
        ))
    return out


def load_burp_xml(path: str | Path) -> list[dict]:
    data = _read_export(path)
    # Burp exports can legitimately include element/attribute DTD schemas.
    # Reject entity declarations, including ASCII markers in UTF-16/32,
    # before ElementTree can expand them. No external resource is fetched.
    if re.search(br"<!\s*ENTITY\b", data.replace(b"\x00", b""), re.I):
        raise TrafficInputError("Burp XML entity declarations are unsupported")
    root = ET.fromstring(data)
    if root.tag != "items":
        raise ValueError("Burp XML requires items root")
    out = []
    for sequence,item in enumerate(root.iterfind(".//item")):
        if sequence >= MAX_TRAFFIC_RECORDS:
            raise TrafficInputError("Traffic export exceeds 10000 records; split it into smaller exports")
        url = item.findtext("url") or ""; method = item.findtext("method") or "GET"; status_text = item.findtext("status") or ""
        req = item.find("request"); resp = item.find("response")
        request = _decode(req.text if req is not None else "", req is not None and req.attrib.get("base64") == "true")
        response = _decode(resp.text if resp is not None else "", resp is not None and resp.attrib.get("base64") == "true")
        out.append(_record(
            url, method, int(status_text) if status_text.isdigit() else None,
            request, response, "burp", sequence=sequence,
            identity=_burp_identity(request),
        ))
    return out


def load_zap_har(path: str | Path) -> list[dict]:
    return [{**x, "source": "zap-har"} for x in load_har(path)]


def ingest_traffic(path: str | Path, kind: str = "auto") -> list[dict]:
    path = Path(path)
    if not path.is_file():
        raise TrafficInputError(f"Traffic file not found or not a regular file: {path}. Export Burp XML/HAR and pass its actual path, or omit --traffic.")
    try:
        if kind == "burp" or (kind == "auto" and path.suffix.lower() == ".xml"):
            return load_burp_xml(path)
        if kind in {"har", "zap"} or path.suffix.lower() == ".har":
            return load_zap_har(path) if kind == "zap" else load_har(path)
    except TrafficInputError:
        raise
    except (OSError, ValueError, ET.ParseError, AttributeError, TypeError, KeyError, RecursionError) as error:
        # Parser diagnostics can contain credentials or captured response text.
        raise TrafficInputError(f"Cannot read traffic file as Burp XML/HAR: {path} ({type(error).__name__}). Check the export format and file permissions.") from None
    raise TrafficInputError(f"Unsupported traffic format: {path}. Use Burp XML or HAR.")
