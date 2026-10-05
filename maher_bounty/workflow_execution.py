"""Execute application-specific access policies and ordered workflow invariants.

Expected behavior comes from the assessment manifest, never a status-code guess.
Credentials stay in memory; persisted evidence contains hashes and assertions.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import ssl
import ipaddress
import threading
import time
from http.cookiejar import CookieJar, Cookie
from http.cookies import SimpleCookie
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, HTTPSHandler

from .differential import compare_responses
from .burp_evidence import _safe_url
from .scope_policy import is_in_scope_url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class InconsistentAccessEvidence(RuntimeError):
    """Repeated forbidden resource proofs disagree."""


def _validate_proxy(proxy):
    if proxy is None:
        return None
    if not isinstance(proxy, dict) or set(proxy) - {"url", "ca_file"} or not isinstance(proxy.get("url"), str):
        raise ValueError("proxy requires url and optional ca_file")
    parsed = urlparse(proxy["url"])
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        port = parsed.port
    except ValueError:
        raise ValueError("proxy requires a literal loopback address and valid port") from None
    if (parsed.scheme != "http" or not loopback or not port or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("proxy must be a credential-free local HTTP listener")
    if "ca_file" in proxy and (not isinstance(proxy["ca_file"], str) or not Path(proxy["ca_file"]).is_file()):
        raise ValueError("proxy CA file is missing")
    return proxy


class LocalProxyHandler(ProxyHandler):
    def proxy_open(self, request, proxy, protocol):
        # Explicit interception must not be bypassed by ambient NO_PROXY.
        # set_proxy preserves HTTPS CONNECT tunnelling and original target TLS.
        request.set_proxy(urlparse(proxy).netloc, "http")
        return None


def _origin(url):
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _protected_headers(identity):
    return {"authorization", "cookie", "host", "proxy-authorization"} | {
        header.lower() for header in identity.get("headers_env", {})}


def _finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _validate_limits(limits):
    keys = {"timeout_seconds", "total_seconds", "interval_seconds", "max_requests"}
    if not isinstance(limits, dict) or set(limits) - keys:
        raise ValueError("workflow limits require supported keys")
    for key, value in limits.items():
        if key == "max_requests":
            if type(value) is not int or value < 1:
                raise ValueError("max_requests must be a positive integer")
        elif (not _finite_number(value)
              or value < 0 or (key != "interval_seconds" and value == 0)):
            raise ValueError("workflow time limits must be finite numbers with positive timeouts and nonnegative interval")


def _wait_for_interval(last, interval, deadline):
    if not _finite_number(interval) or interval < 0:
        raise ValueError("request interval must be finite and nonnegative")
    now = time.monotonic()
    delay = max(0, interval - (now - last))
    if now >= deadline or delay >= deadline - now:
        raise RuntimeError("request pacing exceeds remaining run budget")
    time.sleep(delay)


def _validate_browser_settings(settings):
    supported = {"actions", "wait_for", "wait_for_network_idle", "body_selector", "capture_dom"}
    if not isinstance(settings, dict) or set(settings) - supported:
        raise ValueError("browser settings require supported keys")
    if "wait_for_network_idle" in settings and type(settings["wait_for_network_idle"]) is not bool:
        raise ValueError("wait_for_network_idle must be a boolean")
    for key in ("wait_for", "body_selector"):
        if key in settings and (not isinstance(settings[key], str) or not settings[key].strip()):
            raise ValueError("browser locator must be a nonempty string")
    actions = settings.get("actions", [])
    if not isinstance(actions, list):
        raise ValueError("browser actions must be a list")
    for action in actions:
        if not isinstance(action, dict):
            raise ValueError("browser action must be an object")
        kind = action.get("kind")
        if kind not in ("fill", "click", "check", "select"):
            raise ValueError("unsupported browser action")
        keys = {"kind", "selector"} | ({"value", "value_env"} if kind == "fill" else {"value"} if kind == "select" else set())
        if set(action) - keys or not isinstance(action.get("selector"), str) or not action["selector"].strip():
            raise ValueError("invalid browser action fields or selector")
        if kind == "fill":
            if ("value" in action) == ("value_env" in action):
                raise ValueError("fill requires exactly one value or value_env")
            if "value_env" in action and (not isinstance(action["value_env"], str) or not action["value_env"].strip()):
                raise ValueError("invalid browser value_env")
        if kind in ("fill", "select") and "value_env" not in action and action.get("value") is None:
            raise ValueError("browser action requires a value")
    captures = settings.get("capture_dom", {})
    if not isinstance(captures, dict):
        raise ValueError("capture_dom must be a mapping")
    for variable, capture in captures.items():
        if not isinstance(variable, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
            raise ValueError("invalid DOM capture variable")
        if (not isinstance(capture, dict) or set(capture) - {"selector", "attribute"}
                or not isinstance(capture.get("selector"), str) or not capture["selector"].strip()
                or ("attribute" in capture and (not isinstance(capture["attribute"], str) or not capture["attribute"].strip()))):
            raise ValueError("invalid DOM capture specification")


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous JSON object")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError("nonfinite JSON value")


def _json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def _json_equal(actual, expected):
    # JSON has separate boolean and number types, unlike Python equality.
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return (isinstance(actual, int) or math.isfinite(actual)) and (isinstance(expected, int) or math.isfinite(expected)) and actual == expected
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(_json_equal(actual[k], expected[k]) for k in actual)
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(_json_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _decode_json(body):
    return json.loads(body, object_pairs_hook=_json_pairs, parse_constant=_invalid_json_constant, parse_float=_json_float)


def _validate_pointer(pointer):
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")) or re.search(r"~(?![01])", pointer):
        raise ValueError("invalid JSON Pointer")


def _pointer_value(value, pointer):
    _validate_pointer(pointer)
    if pointer == "":
        return value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", part):
                raise ValueError("invalid JSON array index")
            value = value[int(part)]
        else:
            value = value[part]
    return value


def _json_value(body, pointer):
    return _pointer_value(_decode_json(body), pointer)


def _assertions(response, expected):
    checks = []
    if "statuses" in expected:
        checks.append({"kind": "status", "passed": response["status"] in expected["statuses"]})
    for marker in expected.get("contains", []):
        checks.append({"kind": "contains", "passed": marker in response["body"]})
    for marker in expected.get("absent", []):
        checks.append({"kind": "absent", "passed": marker not in response["body"]})
    json_valid, document = False, None
    if expected.get("json_equals") or expected.get("json_absent") or expected.get("json_number"):
        try:
            document = _decode_json(response["body"])
            json_valid = True
        except (ValueError, TypeError, RecursionError):
            pass
    for pointer, wanted in expected.get("json_equals", {}).items():
        try:
            passed = json_valid and _json_equal(_pointer_value(document, pointer), wanted)
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            passed = False
        checks.append({"kind": "json_equals", "pointer": pointer, "passed": passed})
    for pointer in expected.get("json_absent", []):
        passed = False
        if json_valid:
            try:
                _pointer_value(document, pointer)
            except (KeyError, IndexError):
                passed = True
            except (ValueError, TypeError, RecursionError):
                pass
        checks.append({"kind": "json_absent", "pointer": pointer, "passed": passed})
    for pointer, bounds in expected.get("json_number", {}).items():
        try:
            actual = _pointer_value(document, pointer) if json_valid else None
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            actual = None
        for comparison, bound in bounds.items():
            passed = False
            if _finite_number(actual) and _finite_number(bound):
                passed = {"gt": lambda: actual > bound, "gte": lambda: actual >= bound,
                          "lt": lambda: actual < bound, "lte": lambda: actual <= bound}[comparison]()
            checks.append({"kind": "json_number", "pointer": pointer,
                           "operator": comparison, "passed": passed})
    return checks


def _observation(response, checks):
    body = response["body"].encode("utf-8")
    return {"status": response["status"], "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body), "truncated": response.get("truncated", False), "assertions": checks,
            "network_incomplete": response.get("network_incomplete", False),
            "pending_requests": response.get("pending_requests", 0),
            "representation": "rendered_dom" if response.get("browser_derived") else "http_body"}


def _validate_expectation(expected, *, allow_templates=False):
    supported = {"statuses", "contains", "absent", "json_equals", "json_absent", "json_number"}
    if not isinstance(expected, dict) or not expected or set(expected) - supported:
        raise ValueError("expectations require supported assertion keys")
    count = 0
    for key in ("contains", "absent"):
        if key in expected:
            markers = expected[key]
            if not isinstance(markers, list) or any(not isinstance(m, str) or not m.strip() for m in markers):
                raise ValueError("content assertions require nonempty string markers in a list")
            count += len(markers)
    if "statuses" in expected:
        statuses = expected["statuses"]
        if not isinstance(statuses, list) or not statuses or any(type(s) is not int or not 100 <= s <= 599 for s in statuses):
            raise ValueError("statuses must be a nonempty list of HTTP status integers")
        count += 1
    if "json_equals" in expected:
        values = expected["json_equals"]
        if not isinstance(values, dict) or any(not isinstance(p, str) or (p and not p.startswith("/")) for p in values):
            raise ValueError("json_equals requires JSON Pointer keys")
        try:
            json.dumps(values, allow_nan=False)
        except (ValueError, TypeError, RecursionError):
            raise ValueError("json_equals requires finite JSON values") from None
        count += len(values)
        for pointer in values:
            _validate_pointer(pointer)
    if "json_absent" in expected:
        pointers = expected["json_absent"]
        if not isinstance(pointers, list) or not pointers:
            raise ValueError("json_absent requires a nonempty JSON Pointer list")
        for pointer in pointers:
            _validate_pointer(pointer)
        count += len(pointers)
    if "json_number" in expected:
        values = expected["json_number"]
        if not isinstance(values, dict) or not values:
            raise ValueError("json_number requires a nonempty JSON Pointer mapping")
        for pointer, bounds in values.items():
            _validate_pointer(pointer)
            if not isinstance(bounds, dict) or not bounds or set(bounds) - {"gt", "gte", "lt", "lte"}:
                raise ValueError("json_number requires gt/gte/lt/lte bounds")
            for bound in bounds.values():
                template = allow_templates and isinstance(bound, str) and re.fullmatch(
                    r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", bound)
                if not _finite_number(bound) and not template:
                    raise ValueError("json_number bounds must be finite numbers")
            count += len(bounds)
    if not count:
        raise ValueError("expectations require at least one actual assertion")


def _resolve(value, variables, *, url=False):
    if isinstance(value, dict):
        return {key: _resolve(item, variables, url=(key == "url")) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, variables) for item in value]
    if not isinstance(value, str):
        return value
    exact = re.fullmatch(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", value)
    if exact and not url:
        return variables[exact.group(1)]
    def replace(match):
        text = str(variables[match.group(1)])
        return quote(text, safe="") if url else text
    return re.sub(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", replace, value)


def _template_variables(value):
    if isinstance(value, dict):
        return set().union(*(_template_variables(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_template_variables(item) for item in value))
    if isinstance(value, str):
        return set(re.findall(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", value))
    return set()


def validate_manifest(manifest, scope):
    if not isinstance(manifest, dict):
        raise ValueError("workflow manifest must be an object")
    _validate_limits(manifest.get("limits", {}))
    if manifest.get("engine", "http") not in ("http", "browser"):
        raise ValueError("workflow engine must be http or browser")
    _validate_proxy(manifest.get("proxy"))
    if manifest.get("proxy") and "ca_file" in manifest["proxy"] and manifest.get("engine", "http") == "browser":
        raise ValueError("browser proxy CA must be trusted by Chromium; ca_file is HTTP-only")
    identities = manifest.get("identities", {})
    cases = manifest.get("access_cases", [])
    workflows = manifest.get("workflows", [])
    if not identities or not (cases or workflows):
        raise ValueError("identities and at least one access case or workflow are required")
    names = set()
    requests = []
    for case in cases:
        if case.get("id") in names or not isinstance(case.get("id"), str):
            raise ValueError("case ids must be unique strings")
        names.add(case["id"])
        allowed, denied = case.get("allowed", []), case.get("denied", [])
        if not allowed or not denied or set(allowed) & set(denied):
            raise ValueError("access cases require disjoint allowed and denied identities")
        if any(name not in identities for name in allowed + denied):
            raise ValueError("unknown identity")
        _validate_expectation(case.get("proof"))
        if not case.get("proof", {}).get("contains") and not case.get("proof", {}).get("json_equals"):
            raise ValueError("access cases require a resource-specific content proof")
        request = case.get("request", {})
        if request.get("method", "GET").upper() not in {"GET", "HEAD"}:
            raise ValueError("access matrix uses read-only requests; use workflows for mutations")
        if request.get("browser", {}).get("actions"):
            raise ValueError("access matrices cannot repeat form actions; use workflows")
        requests.extend((request, name) for name in allowed + denied)
    for workflow in workflows:
        if workflow.get("id") in names or not isinstance(workflow.get("id"), str):
            raise ValueError("workflow ids must be unique strings")
        names.add(workflow["id"])
        if workflow.get("identity") not in identities or not workflow.get("steps"):
            raise ValueError("workflow requires a known identity and ordered steps")
        cleanup = workflow.get("cleanup_steps", [])
        if not isinstance(workflow["steps"], list) or not isinstance(cleanup, list):
            raise ValueError("workflow steps and cleanup_steps must be lists")
        initial = workflow.get("variables", {})
        if not isinstance(initial, dict) or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) for key in initial):
            raise ValueError("workflow variables require valid named values")
        available = set(initial)
        for step in workflow["steps"] + cleanup:
            if not isinstance(step, dict):
                raise ValueError("workflow steps must be objects")
            if not step.get("expect"):
                raise ValueError("every workflow step requires expected behavior")
            _validate_expectation(step["expect"], allow_templates=True)
            captures = step.get("capture", {})
            if not isinstance(captures, dict):
                raise ValueError("capture requires a JSON Pointer mapping")
            for variable, pointer in captures.items():
                if not isinstance(variable, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
                    raise ValueError("invalid capture variable name")
                _validate_pointer(pointer)
            request = step.get("request", {})
            settings = request.get("browser", {})
            _validate_browser_settings(settings)
            dom_captures = settings.get("capture_dom", {})
            if set(captures) & set(dom_captures):
                raise ValueError("a step cannot capture the same variable from JSON and DOM")
            if (_template_variables(request) | _template_variables(step["expect"])) - available:
                raise ValueError("workflow uses a variable before initialization or an earlier capture")
            available.update(captures)
            available.update(dom_captures)
            name = step.get("identity", workflow["identity"])
            if name not in identities:
                raise ValueError("workflow step requires a known identity")
            requests.append((step.get("request", {}), name))
    for request, name in requests:
        settings = request.get("browser", {})
        _validate_browser_settings(settings)
        if settings and manifest.get("engine", "http") != "browser":
            raise ValueError("browser settings require engine=browser")
        url = request.get("url", "")
        if not is_in_scope_url(url, scope) or urlparse(url).fragment:
            raise ValueError("request URL is outside scope or contains a fragment")
        # Credential contexts are pinned to a full origin, including scheme/port.
        origin = identities[name].get("origin")
        if not origin or _origin(url) != _origin(origin):
            raise ValueError("identity origin must match the request origin")
        method = request.get("method", "GET").upper()
        if manifest.get("engine") == "browser" and (method != "GET" or "body" in request):
            raise ValueError("browser requests require GET navigation; use browser form actions for mutations")
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        if any(k.lower() in _protected_headers(identities[name]) for k in request.get("headers", {})):
            raise ValueError("request headers must not override identity credentials or Host")
    return manifest


class Transport:
    def __init__(self, identities, timeout=10, max_bytes=1048576, interval=0.2, budget=200, deadline=None, proxy=None):
        self.identities = identities
        self.proxy = _validate_proxy(proxy)
        self.tls_context = ssl.create_default_context(cafile=self.proxy.get("ca_file") if self.proxy else None)
        self.timeout, self.max_bytes, self.interval, self.budget = timeout, max_bytes, interval, budget
        self.count, self.last = 0, 0.0
        self.deadline = deadline if deadline is not None else float("inf")
        self.openers = {}
        self.headers = {}
        self.seed_cookies = {}
        for name, identity in identities.items():
            self.headers[name] = {}
            self.seed_cookies[name] = []
            for header, env_name in identity.get("headers_env", {}).items():
                value = os.environ.get(env_name)
                if not value:
                    raise ValueError(f"missing credential environment variable: {env_name}")
                if header.lower() in {"host", "proxy-authorization"} or "\r" in value or "\n" in value:
                    raise ValueError("invalid identity header")
                if header.lower() == "cookie":
                    parsed = SimpleCookie()
                    parsed.load(value)
                    if not parsed:
                        raise ValueError("invalid HTTP cookie credential")
                    origin = urlparse(identity["origin"])
                    host = origin.hostname
                    domain = host if "." in host or ":" in host else host + ".local"
                    for key, morsel in parsed.items():
                        self.seed_cookies[name].append(Cookie(0, key, morsel.value, None, False, domain, False, False,
                                                              "/", True, origin.scheme == "https", None, True,
                                                              None, None, {}, False))
                else:
                    self.headers[name][header] = value
            self.reset(name)

    def reset(self, name):
        jar = CookieJar()
        for cookie in self.seed_cookies[name]:
            jar.set_cookie(cookie)
        proxy_handler = LocalProxyHandler({"http": self.proxy["url"], "https": self.proxy["url"]}) if self.proxy else ProxyHandler({})
        self.openers[name] = build_opener(proxy_handler, HTTPSHandler(context=self.tls_context), NoRedirect(), HTTPCookieProcessor(jar))

    def __call__(self, name, spec):
        parsed = urlparse(spec["url"])
        if (parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None
                or _origin(spec["url"]) != _origin(self.identities[name]["origin"])):
            raise ValueError("HTTP request outside identity origin")
        if any(k.lower() in _protected_headers(self.identities[name]) for k in spec.get("headers", {})):
            raise ValueError("request headers cannot override identity credentials")
        if self.count >= self.budget:
            raise RuntimeError("request budget exhausted")
        _wait_for_interval(self.last, self.interval, self.deadline)
        if time.monotonic() >= self.deadline:
            raise RuntimeError("HTTP run deadline exhausted")
        self.count += 1
        self.last = time.monotonic()
        read_deadline = min(self.deadline, self.last + self.timeout)
        headers = {**self.headers[name], **spec.get("headers", {})}
        body = spec.get("body")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            headers.setdefault("Content-Type", "application/json")
        request = Request(spec["url"], data=body.encode() if isinstance(body, str) else None,
                          headers=headers, method=spec.get("method", "GET").upper())
        try:
            response = self.openers[name].open(request, timeout=max(0.001, read_deadline - time.monotonic()))
        except HTTPError as exc:
            response = exc
        with response:
            raw = self._read_body(response, read_deadline)
            return {"status": response.code, "body": raw[:self.max_bytes].decode("utf-8", errors="replace"),
                    "headers": dict(response.headers), "truncated": len(raw) > self.max_bytes}

    def _read_body(self, response, deadline):
        # HTTPError wraps HTTPResponse; locate its socket to narrow each read
        # to the remaining elapsed-time budget rather than reset inactivity.
        stream = response
        sock = None
        for _ in range(3):
            stream = getattr(stream, "fp", None)
            if stream is None:
                break
            sock = getattr(getattr(stream, "raw", None), "_sock", None)
            if sock is not None:
                break
        read = getattr(response, "read1", response.read)
        actual_response = getattr(read, "__self__", response)
        timer = None
        if sock is not None:
            # Chunk framing may internally perform multiple reads. Interrupt
            # the body socket at the elapsed deadline, even during framing.
            def interrupt():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(0, deadline - time.monotonic()), interrupt)
            timer.daemon = True
            timer.start()
        try:
            return self._read_chunks(read, actual_response, sock, deadline)
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()

    def _read_chunks(self, read, actual_response, sock, deadline):
        raw = bytearray()
        while len(raw) <= self.max_bytes:
            if callable(getattr(actual_response, "isclosed", None)) and actual_response.isclosed():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP response read deadline exhausted")
            if sock is not None:
                sock.settimeout(remaining)
            try:
                chunk = read(min(65536, self.max_bytes + 1 - len(raw)))
            except (OSError, HTTPException):
                if time.monotonic() >= deadline:
                    raise TimeoutError("HTTP response read deadline exhausted") from None
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError("HTTP response read deadline exhausted")
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) <= self.max_bytes and (getattr(actual_response, "length", None) or 0) > 0:
            raise RuntimeError("incomplete HTTP response body")
        return bytes(raw)


def execute_workflows(manifest, scope, out_dir, *, authorized=False, transport=None):
    if not authorized:
        raise ValueError("workflow execution requires explicit authorization")
    validate_manifest(manifest, scope)
    engine = manifest.get("engine", "http")
    if engine not in {"http", "browser"}:
        raise ValueError("unknown workflow engine")
    browser = None
    if engine == "browser" and transport is None:
        from .browser_runtime import BrowserTransport
        limits = manifest.get("limits", {})
        browser = BrowserTransport(manifest["identities"], scope,
                                   timeout=max(1, min(float(limits.get("timeout_seconds", 10)), 60)),
                                   budget=max(1, min(int(limits.get("max_requests", 200)), 2000)),
                                   total_seconds=max(1, min(float(limits.get("total_seconds", 300)), 3600)),
                                   interval=max(0.1, float(limits.get("interval_seconds", 0.2))), proxy=manifest.get("proxy"))
        transport = browser
    try:
        return _execute_workflows(manifest, scope, out_dir, authorized=authorized, transport=transport)
    finally:
        if browser:
            browser.close()


def _execute_workflows(manifest, scope, out_dir, *, authorized=False, transport=None):
    if not authorized:
        raise ValueError("workflow execution requires explicit authorization")
    validate_manifest(manifest, scope)
    limits = manifest.get("limits", {})
    timeout = max(1, min(float(limits.get("timeout_seconds", 10)), 60))
    budget = max(1, min(int(limits.get("max_requests", 200)), 2000))
    deadline = time.monotonic() + max(1, min(float(limits.get("total_seconds", 300)), 3600))
    sender = transport or Transport(manifest["identities"], timeout=timeout, budget=budget,
                                   interval=max(0.1, float(limits.get("interval_seconds", 0.2))), deadline=deadline,
                                   proxy=manifest.get("proxy"))
    observations, findings, decisions, cleanup_decisions = [], [], [], []
    count = 0

    def send(identity, spec):
        nonlocal count
        if count >= budget or time.monotonic() >= deadline:
            raise RuntimeError("assessment budget exhausted")
        count += 1
        return sender(identity, spec)

    def perform_step(workflow, step, index, variables, rows):
        name = step.get("identity", workflow["identity"])
        request = _resolve(step["request"], variables)
        if (not is_in_scope_url(request["url"], scope)
                or _origin(request["url"]) != _origin(manifest["identities"][name]["origin"])):
            raise ValueError("resolved workflow request escaped scope or origin")
        expected = _resolve(step["expect"], variables)
        _validate_expectation(expected)
        response = send(name, request)
        checks = _assertions(response, expected)
        rows.append({"step": index, "identity": name, **_observation(response, checks)})
        if response.get("truncated") or response.get("network_incomplete") or not checks:
            raise RuntimeError("incomplete workflow evidence")
        passed = all(c["passed"] for c in checks)
        if passed:
            if step.get("capture"):
                document = _decode_json(response["body"])
                for variable, pointer in step["capture"].items():
                    variables[variable] = _pointer_value(document, pointer)
            variables.update(response.get("captured", {}))
        return passed

    for case in manifest.get("access_cases", []):
        rows, control = [], None
        try:
            # Repeat the allowed baseline to reject unstable or invalid controls.
            for name in case["allowed"]:
                for repeat in range(2):
                    response = send(name, case["request"])
                    checks = _assertions(response, {"statuses": [200], **case["proof"]})
                    valid = bool(checks) and all(c["passed"] for c in checks) and not response.get("truncated") and not response.get("network_incomplete")
                    rows.append({"identity": name, "role": "allowed", "repeat": repeat,
                                 **_observation(response, checks)})
                    if not valid:
                        raise RuntimeError("allowed baseline failed resource proof")
                    control = response
            for name in case["denied"]:
                hits = []
                for repeat in range(2):
                    response = send(name, case["request"])
                    checks = _assertions(response, {"statuses": [200], **case["proof"]})
                    hit = all(c["passed"] for c in checks)
                    hits.append(hit)
                    rows.append({"identity": name, "role": "denied", "repeat": repeat,
                                 **_observation(response, checks), "resource_proof_passed": hit,
                                 "differential": compare_responses(control, response)})
                    if response.get("truncated") or response.get("network_incomplete"):
                        raise RuntimeError("incomplete denied resource evidence")
                if any(hits) and not all(hits):
                    raise InconsistentAccessEvidence("forbidden resource proof changed across repeats")
                if all(hits):
                    findings.append({"source": "workflow_execution", "title": f"Access policy violated: {case['id']} ({name})",
                                     "target": _safe_url(case["request"]["url"]), "severity": "high", "validated": True,
                                     "evidence": {"case_id": case["id"], "identity": name, "observations": rows.copy()},
                                     "basis": "explicit policy, valid allowed controls, repeatable forbidden resource proof"})
            decisions.append({"id": case["id"], "status": "completed"})
        except (OSError, URLError, RuntimeError, ValueError, HTTPException) as exc:
            # Do not persist exception text, which can contain credential values.
            decisions.append({"id": case["id"], "status": "inconclusive", "error_type": type(exc).__name__})
        observations.append({"id": case["id"], "observations": rows})

    for workflow in manifest.get("workflows", []):
        rows = []
        variables = dict(workflow.get("variables", {}))
        try:
            # Reset each participating session once, preserving it when switching
            # back to that identity later in the same application lifecycle.
            if hasattr(sender, "reset"):
                participants = dict.fromkeys(step.get("identity", workflow["identity"]) for step in workflow["steps"] + workflow.get("cleanup_steps", []))
                for name in participants:
                    sender.reset(name)
            for index, step in enumerate(workflow["steps"]):
                if not perform_step(workflow, step, index, variables, rows):
                    findings.append({"source": "workflow_execution", "title": f"Workflow invariant violated: {workflow['id']} step {index}",
                                     "target": _safe_url(step["request"]["url"]), "severity": "medium", "validated": False,
                                     "evidence": {"workflow_id": workflow["id"], "observations": rows.copy()},
                                     "basis": "explicit invariant failed; requires impact review"})
                    decisions.append({"id": workflow["id"], "status": "invariant_failed", "step": index})
                    break
            else:
                decisions.append({"id": workflow["id"], "status": "completed"})
        except (OSError, URLError, RuntimeError, ValueError, KeyError, IndexError, TypeError, HTTPException) as exc:
            decisions.append({"id": workflow["id"], "status": "inconclusive", "error_type": type(exc).__name__})
        entry = {"id": workflow["id"], "observations": rows}
        if workflow.get("cleanup_steps"):
            cleanup_rows = []
            try:
                for index, step in enumerate(workflow["cleanup_steps"]):
                    if not perform_step(workflow, step, index, variables, cleanup_rows):
                        cleanup_decisions.append({"id": workflow["id"], "status": "invariant_failed", "step": index})
                        break
                else:
                    cleanup_decisions.append({"id": workflow["id"], "status": "completed"})
            except (OSError, URLError, RuntimeError, ValueError, KeyError, IndexError, TypeError, HTTPException) as exc:
                cleanup_decisions.append({"id": workflow["id"], "status": "inconclusive", "error_type": type(exc).__name__})
            entry["cleanup_observations"] = cleanup_rows
        observations.append(entry)

    result = {"status": "partial" if any(d["status"] == "inconclusive" for d in decisions) or any(d["status"] != "completed" for d in cleanup_decisions) else "completed",
              "requests": count, "decisions": decisions, "observations": observations, "findings": findings}
    if cleanup_decisions:
        result["cleanup_decisions"] = cleanup_decisions
    if hasattr(sender, "summary"):
        result["transport"] = sender.summary()
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "workflow-evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
