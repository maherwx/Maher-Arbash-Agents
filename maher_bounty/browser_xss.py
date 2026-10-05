"""Bounded query-input execution verification using the scoped browser runtime."""
import json
import secrets
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .burp_evidence import _safe_url
from .scope_policy import is_in_scope_url


def run_browser_xss(url, out_dir, *, scope, authorized=False):
    if not authorized:
        raise ValueError("browser execution checks require authorization")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment or not is_in_scope_url(url, scope):
        raise ValueError("browser execution check requires an in-scope HTTP URL")
    result = {"tool": "browser-xss", "status": "ok", "target": _safe_url(url),
              "findings": [], "checks": [], "coverage": "first_three_query_occurrences_html_event_context"}
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        result.update(status="blocked", reason="query_parameter_limit")
        return result
    if not pairs:
        result["status"] = "skipped"
        result["reason"] = "no_query_parameters"
        return result
    from .browser_runtime import BrowserTransport
    sender = None
    try:
        sender = BrowserTransport({"probe": {"origin": urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))}},
                                  scope, timeout=3, budget=60, total_seconds=60, interval=0.2)
        def navigate(index, value):
            changed = list(pairs)
            changed[index] = (pairs[index][0], value)
            probe_url = urlunsplit(parsed._replace(query=urlencode(changed)))
            sender.reset("probe")
            response = sender("probe", {"url": probe_url})
            if response.get("network_incomplete") or response.get("truncated"):
                raise RuntimeError("incomplete browser evidence")
            return response
        for index, (parameter, _) in enumerate(pairs[:3]):
            check = {"parameter": parameter, "occurrence": index, "status": "not_confirmed", "proofs": []}
            result["checks"].append(check)
            try:
                control_attr = "data-maher-" + secrets.token_hex(12)
                navigate(index, "maher-control-" + secrets.token_hex(12))
                if sender.pages["probe"].locator("html").get_attribute(control_attr) is not None:
                    raise RuntimeError("invalid negative control")
                check["control_passed"] = True
                for _ in range(2):
                    attr, token = "data-maher-" + secrets.token_hex(12), secrets.token_hex(16)
                    payload = f'<svg onload="document.documentElement.setAttribute(\'{attr}\',\'{token}\')"></svg>'
                    response = navigate(index, payload)
                    observed = sender.pages["probe"].locator("html").get_attribute(attr)
                    if observed != token:
                        break
                    check["proofs"].append({"attribute": attr, "token": token, "status": response["status"],
                                            "payload": payload})
                if len(check["proofs"]) == 2:
                    check["status"] = "confirmed_execution"
                    result["findings"].append({"source": "browser-xss", "title": f"Query parameter {index + 1} executes JavaScript in browser",
                        "severity": "medium", "target": _safe_url(url), "validated": True,
                        "evidence": {"parameter": parameter, "occurrence": index, "control_passed": True,
                                     "proofs": list(check["proofs"])},
                        "basis": "two fresh browser contexts executed distinct DOM marker probes; impact requires review"})
            except Exception as exc:
                check["status"] = "inconclusive"
                check["error_type"] = type(exc).__name__
                result["status"] = "partial"
    except Exception as exc:
        result["status"] = "blocked"
        result["error_type"] = type(exc).__name__
    finally:
        if sender is not None:
            sender.close()
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "browser-xss.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
