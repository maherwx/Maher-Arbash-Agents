from __future__ import annotations

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse


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
                if str(row.get("name", "")).lower() in sensitive:
                    row["value"] = "[redacted]"
            for row in message.get("cookies", []):
                row["value"] = "[redacted]"
            return json.dumps(message, ensure_ascii=False)
        except (ValueError, AttributeError, TypeError):
            return raw
    boundary = re.search(r"\r?\n\r?\n", raw)
    head = raw[:boundary.start()] if boundary else raw
    tail = raw[boundary.start():] if boundary else ""
    for name in sensitive:
        head = re.sub(r"(?im)^(" + re.escape(name) + r":)[^\r\n]*", r"\1 [redacted]", head)
    return head + tail


def _har_headers(req: dict) -> dict[str,str]:
    return {str(x.get("name") or "").lower():str(x.get("value") or "") for x in req.get("headers",[]) if x.get("name")}


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
    match = session_cookie.search(cookie)
    if match:
        return _stable_identity(match.group(1))
    authorization = headers.get("authorization", "")
    return _stable_identity(authorization) if authorization else None


def _har_identity(req: dict) -> str | None:
    return _identity_from_headers(_har_headers(req))


def _burp_identity(raw: str) -> str | None:
    value = str(raw or "")
    boundary = re.search(r"\r?\n\r?\n", value)
    head = value[:boundary.start()] if boundary else value
    headers = {}
    for line in head.splitlines()[1:]:
        if ":" in line:
            name, item = line.split(":", 1)
            headers[name.strip().lower()] = item.strip()
    return _identity_from_headers(headers)
def load_har(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for sequence,entry in enumerate(data.get("log", {}).get("entries", [])):
        req, resp = entry.get("request", {}), entry.get("response", {})
        out.append(_record(
            req.get("url", ""), req.get("method", "GET"), resp.get("status"),
            json.dumps(req, ensure_ascii=False), json.dumps(resp, ensure_ascii=False), "har",
            timestamp=entry.get("startedDateTime"), sequence=sequence, identity=_har_identity(req),
        ))
    return out


def load_burp_xml(path: str | Path) -> list[dict]:
    root = ET.parse(path).getroot()
    out = []
    for sequence,item in enumerate(root.findall(".//item")):
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
    if kind == "burp" or (kind == "auto" and path.suffix.lower() == ".xml"):
        return load_burp_xml(path)
    if kind in {"har", "zap"} or path.suffix.lower() == ".har":
        return load_zap_har(path) if kind == "zap" else load_har(path)
    raise ValueError(f"Unsupported traffic format: {path}")
