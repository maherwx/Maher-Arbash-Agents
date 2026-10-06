"""Bounded query-input execution verification using the scoped browser runtime."""
import secrets
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .burp_evidence import _safe_url
from .scope_policy import is_in_scope_url
from .artifact_io import write_json_atomic
from .workflow_execution import _origin, _assertions, _validate_expectation, _validate_browser_settings


def load_browser_xss_profile(manifest, scope):
    """Resolve one explicitly selected supplied identity; never infer login."""
    if "browser_xss_profile" not in manifest:
        return None
    profile = manifest["browser_xss_profile"]
    if not isinstance(profile, dict) or set(profile) != {"identity", "session_request", "session_proof"}:
        raise ValueError("browser_xss_profile requires identity, session_request and session_proof")
    name = profile["identity"]
    if not isinstance(name, str) or name not in manifest.get("identities", {}):
        raise ValueError("browser XSS profile requires a supplied identity")
    identity = manifest["identities"][name]
    if not identity.get("headers_env") and not identity.get("storage_state"):
        raise ValueError("browser XSS profile requires supplied credential headers or storage state")
    request = profile["session_request"]
    if (not isinstance(request, dict) or set(request) - {"url", "method", "browser"}
            or request.get("method", "GET") != "GET"):
        raise ValueError("session control requires a fixed GET navigation")
    settings = request.get("browser", {})
    _validate_browser_settings(settings)
    if settings.get("actions") or settings.get("capture_dom"):
        raise ValueError("session control cannot perform actions or capture variables")
    url = request.get("url")
    if not isinstance(url, str) or not is_in_scope_url(url, scope) or _origin(url) != _origin(identity["origin"]):
        raise ValueError("session control must match supplied identity origin and scope")
    parsed = urlsplit(url)
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("session control URL cannot contain credentials or fragment")
    proof = profile["session_proof"]
    _validate_expectation(proof)
    if not proof.get("contains") and not proof.get("json_equals"):
        raise ValueError("session control requires explicit positive content proof")
    resolved = {"identity_name": name, "identity": identity, "session_request": request,
                "session_proof": proof, "proxy": manifest.get("proxy")}
    if resolved["proxy"] and "ca_file" in resolved["proxy"]:
        raise ValueError("authenticated browser checks require a CA trusted by Chromium; ca_file is HTTP-only")
    headers = identity.get("headers_env", {})
    if not isinstance(headers, dict):
        raise ValueError("browser identity headers_env must be a mapping")
    credentials = {}
    for header, env_name in headers.items():
        if not isinstance(header, str) or not isinstance(env_name, str):
            raise ValueError("browser identity header and environment names must be strings")
        value = os.environ.get(env_name)
        if not value or "\r" in value or "\n" in value or header.lower() in {"host", "proxy-authorization"}:
            raise ValueError("browser identity credential is missing or invalid")
        credentials[header] = hashlib.sha256(value.encode()).hexdigest()
    state_digest = None
    if identity.get("storage_state"):
        with Path(identity["storage_state"]).open("rb") as stream:
            state = stream.read(8 * 1024 * 1024 + 1)
        if len(state) > 8 * 1024 * 1024:
            raise ValueError("browser storage state exceeds its byte limit")
        state_digest = hashlib.sha256(state).hexdigest()
    binding = {"profile": resolved, "credential_digests": credentials, "storage_state_sha256": state_digest}
    resolved["profile_sha256"] = hashlib.sha256(json.dumps(binding, sort_keys=True, allow_nan=False).encode()).hexdigest()
    return resolved


def run_browser_xss(url, out_dir, *, scope, authorized=False, profile=None):
    if not authorized:
        raise ValueError("browser execution checks require authorization")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment or not is_in_scope_url(url, scope):
        raise ValueError("browser execution check requires an in-scope HTTP URL")
    tool = "browser-xss-auth" if profile is not None else "browser-xss"
    result = {"tool": tool, "status": "ok", "target": _safe_url(url),
              "findings": [], "checks": [], "coverage": "first_three_query_occurrences_html_event_context"}
    identity = profile["identity"] if profile is not None else {"origin": urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))}
    if profile is not None:
        result["identity"] = profile["identity_name"]
        result["profile_sha256"] = profile["profile_sha256"]
        if _origin(url) != _origin(identity["origin"]):
            result.update(status="blocked", reason="identity_origin_mismatch")
            return result
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
        sender = BrowserTransport({"probe": identity},
                                  scope, timeout=3, budget=60, total_seconds=60, interval=0.2,
                                  **({"proxy": profile.get("proxy")} if profile is not None else {}))
        def navigate(index, value):
            changed = list(pairs)
            changed[index] = (pairs[index][0], value)
            probe_url = urlunsplit(parsed._replace(query=urlencode(changed)))
            sender.reset("probe")
            if profile is not None:
                control = sender("probe", profile["session_request"])
                checks = _assertions(control, {"statuses": [200], **profile["session_proof"]})
                if (control["status"] != 200 or control.get("network_incomplete") or control.get("truncated")
                        or not checks or not all(check["passed"] for check in checks)):
                    raise RuntimeError("supplied session control failed")
            response = sender("probe", {"url": probe_url})
            if profile is not None and response["status"] != 200:
                raise RuntimeError("authenticated probe did not return HTTP 200")
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
                    result["findings"].append({"source": tool, "title": f"Query parameter {index + 1} executes JavaScript in browser",
                        "severity": "medium", "target": _safe_url(url), "validated": True,
                        "evidence": {"parameter": parameter, "occurrence": index, "control_passed": True,
                                     "proofs": list(check["proofs"]),
                                     "identity": profile["identity_name"] if profile is not None else "anonymous",
                                     "session_control_required": profile is not None},
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
    write_json_atomic(root / "browser-xss.json", result)
    return result
