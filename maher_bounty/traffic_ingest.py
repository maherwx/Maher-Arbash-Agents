from __future__ import annotations

import base64
import json
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


def _record(url: str, method: str = "GET", status: int | None = None, request: str = "", response: str = "", source: str = "unknown") -> dict:
    u = urlparse(url)
    return {
        "source": source,
        "url": url,
        "host": u.netloc,
        "path": u.path or "/",
        "method": method.upper(),
        "status": status,
        "request_raw": request,
        "response_raw": response,
    }


def load_har(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for entry in data.get("log", {}).get("entries", []):
        req, resp = entry.get("request", {}), entry.get("response", {})
        out.append(_record(req.get("url", ""), req.get("method", "GET"), resp.get("status"), json.dumps(req, ensure_ascii=False), json.dumps(resp, ensure_ascii=False), "har"))
    return out


def load_burp_xml(path: str | Path) -> list[dict]:
    root = ET.parse(path).getroot()
    out = []
    for item in root.findall(".//item"):
        url = item.findtext("url") or ""
        method = item.findtext("method") or "GET"
        status_text = item.findtext("status") or ""
        req = item.find("request"); resp = item.find("response")
        request = _decode(req.text if req is not None else "", req is not None and req.attrib.get("base64") == "true")
        response = _decode(resp.text if resp is not None else "", resp is not None and resp.attrib.get("base64") == "true")
        out.append(_record(url, method, int(status_text) if status_text.isdigit() else None, request, response, "burp"))
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
