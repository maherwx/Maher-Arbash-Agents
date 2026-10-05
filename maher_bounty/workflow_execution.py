"""Execute application-specific access policies and ordered workflow invariants.

Expected behavior comes from the assessment manifest, never a status-code guess.
Credentials stay in memory; persisted evidence contains hashes and assertions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler

from .differential import compare_responses
from .scope_policy import is_in_scope_url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origin(url):
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _json_value(body, pointer):
    value = json.loads(body)
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with /")
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _assertions(response, expected):
    checks = []
    if "statuses" in expected:
        checks.append({"kind": "status", "passed": response["status"] in expected["statuses"]})
    for marker in expected.get("contains", []):
        checks.append({"kind": "contains", "passed": marker in response["body"]})
    for marker in expected.get("absent", []):
        checks.append({"kind": "absent", "passed": marker not in response["body"]})
    for pointer, wanted in expected.get("json_equals", {}).items():
        try:
            passed = _json_value(response["body"], pointer) == wanted
        except (ValueError, KeyError, IndexError, TypeError):
            passed = False
        checks.append({"kind": "json_equals", "pointer": pointer, "passed": passed})
    return checks


def _observation(response, checks):
    body = response["body"].encode("utf-8")
    return {"status": response["status"], "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body), "truncated": response.get("truncated", False), "assertions": checks}


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


def validate_manifest(manifest, scope):
    if not isinstance(manifest, dict):
        raise ValueError("workflow manifest must be an object")
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
        if not case.get("proof", {}).get("contains") and not case.get("proof", {}).get("json_equals"):
            raise ValueError("access cases require a resource-specific content proof")
        request = case.get("request", {})
        if request.get("method", "GET").upper() not in {"GET", "HEAD"}:
            raise ValueError("access matrix uses read-only requests; use workflows for mutations")
        requests.extend((request, name) for name in allowed + denied)
    for workflow in workflows:
        if workflow.get("id") in names or not isinstance(workflow.get("id"), str):
            raise ValueError("workflow ids must be unique strings")
        names.add(workflow["id"])
        if workflow.get("identity") not in identities or not workflow.get("steps"):
            raise ValueError("workflow requires a known identity and ordered steps")
        for step in workflow["steps"]:
            if not step.get("expect"):
                raise ValueError("every workflow step requires expected behavior")
            requests.append((step.get("request", {}), workflow["identity"]))
    for request, name in requests:
        url = request.get("url", "")
        if not is_in_scope_url(url, scope) or urlparse(url).fragment:
            raise ValueError("request URL is outside scope or contains a fragment")
        # Credential contexts are pinned to a full origin, including scheme/port.
        origin = identities[name].get("origin")
        if not origin or _origin(url) != _origin(origin):
            raise ValueError("identity origin must match the request origin")
        method = request.get("method", "GET").upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        if any(k.lower() in {"authorization", "cookie", "host", "proxy-authorization"} for k in request.get("headers", {})):
            raise ValueError("request headers must not override identity credentials or Host")
    return manifest


class Transport:
    def __init__(self, identities, timeout=10, max_bytes=1048576, interval=0.2, budget=200):
        self.identities = identities
        self.timeout, self.max_bytes, self.interval, self.budget = timeout, max_bytes, interval, budget
        self.count, self.last = 0, 0.0
        self.openers = {}
        self.headers = {}
        for name, identity in identities.items():
            self.headers[name] = {}
            for header, env_name in identity.get("headers_env", {}).items():
                value = os.environ.get(env_name)
                if not value:
                    raise ValueError(f"missing credential environment variable: {env_name}")
                if header.lower() in {"host", "proxy-authorization"} or "\r" in value or "\n" in value:
                    raise ValueError("invalid identity header")
                self.headers[name][header] = value
            self.openers[name] = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))

    def reset(self, name):
        self.openers[name] = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))

    def __call__(self, name, spec):
        if self.count >= self.budget:
            raise RuntimeError("request budget exhausted")
        time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
        self.count += 1
        self.last = time.monotonic()
        headers = {**self.headers[name], **spec.get("headers", {})}
        body = spec.get("body")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            headers.setdefault("Content-Type", "application/json")
        request = Request(spec["url"], data=body.encode() if isinstance(body, str) else None,
                          headers=headers, method=spec.get("method", "GET").upper())
        try:
            response = self.openers[name].open(request, timeout=self.timeout)
        except HTTPError as exc:
            response = exc
        with response:
            raw = response.read(self.max_bytes + 1)
            return {"status": response.code, "body": raw[:self.max_bytes].decode("utf-8", errors="replace"),
                    "headers": dict(response.headers), "truncated": len(raw) > self.max_bytes}


def execute_workflows(manifest, scope, out_dir, *, authorized=False, transport=None):
    if not authorized:
        raise ValueError("workflow execution requires explicit authorization")
    validate_manifest(manifest, scope)
    limits = manifest.get("limits", {})
    timeout = max(1, min(float(limits.get("timeout_seconds", 10)), 60))
    budget = max(1, min(int(limits.get("max_requests", 200)), 2000))
    deadline = time.monotonic() + max(1, min(float(limits.get("total_seconds", 300)), 3600))
    sender = transport or Transport(manifest["identities"], timeout=timeout, budget=budget,
                                   interval=max(0.1, float(limits.get("interval_seconds", 0.2))))
    observations, findings, decisions = [], [], []
    count = 0

    def send(identity, spec):
        nonlocal count
        if count >= budget or time.monotonic() >= deadline:
            raise RuntimeError("assessment budget exhausted")
        count += 1
        return sender(identity, spec)

    for case in manifest.get("access_cases", []):
        rows, control = [], None
        try:
            # Repeat the allowed baseline to reject unstable or invalid controls.
            for name in case["allowed"]:
                for repeat in range(2):
                    response = send(name, case["request"])
                    checks = _assertions(response, {"statuses": [200], **case["proof"]})
                    valid = bool(checks) and all(c["passed"] for c in checks) and not response.get("truncated")
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
                    hit = all(c["passed"] for c in checks) and not response.get("truncated")
                    hits.append(hit)
                    rows.append({"identity": name, "role": "denied", "repeat": repeat,
                                 **_observation(response, checks), "differential": compare_responses(control, response)})
                if all(hits):
                    findings.append({"source": "workflow_execution", "title": f"Access policy violated: {case['id']} ({name})",
                                     "target": case["request"]["url"], "severity": "high", "validated": True,
                                     "evidence": {"case_id": case["id"], "identity": name, "observations": rows.copy()},
                                     "basis": "explicit policy, valid allowed controls, repeatable forbidden resource proof"})
            decisions.append({"id": case["id"], "status": "completed"})
        except (OSError, URLError, RuntimeError, ValueError) as exc:
            # Do not persist exception text, which can contain credential values.
            decisions.append({"id": case["id"], "status": "inconclusive", "error_type": type(exc).__name__})
        observations.append({"id": case["id"], "observations": rows})

    for workflow in manifest.get("workflows", []):
        rows = []
        name = workflow["identity"]
        variables = dict(workflow.get("variables", {}))
        if hasattr(sender, "reset"):
            sender.reset(name)
        try:
            for index, step in enumerate(workflow["steps"]):
                request = _resolve(step["request"], variables)
                if (not is_in_scope_url(request["url"], scope)
                        or _origin(request["url"]) != _origin(manifest["identities"][name]["origin"])):
                    raise ValueError("resolved workflow request escaped scope or origin")
                response = send(name, request)
                checks = _assertions(response, _resolve(step["expect"], variables))
                rows.append({"step": index, **_observation(response, checks)})
                if response.get("truncated") or not checks:
                    raise RuntimeError("incomplete workflow evidence")
                if not all(c["passed"] for c in checks):
                    findings.append({"source": "workflow_execution", "title": f"Workflow invariant violated: {workflow['id']} step {index}",
                                     "target": step["request"]["url"], "severity": "medium", "validated": False,
                                     "evidence": {"workflow_id": workflow["id"], "observations": rows.copy()},
                                     "basis": "explicit invariant failed; requires impact review"})
                    decisions.append({"id": workflow["id"], "status": "invariant_failed", "step": index})
                    break
                for variable, pointer in step.get("capture", {}).items():
                    variables[variable] = _json_value(response["body"], pointer)
            else:
                decisions.append({"id": workflow["id"], "status": "completed"})
        except (OSError, URLError, RuntimeError, ValueError, KeyError, IndexError, TypeError) as exc:
            decisions.append({"id": workflow["id"], "status": "inconclusive", "error_type": type(exc).__name__})
        observations.append({"id": workflow["id"], "observations": rows})

    result = {"status": "partial" if any(d["status"] == "inconclusive" for d in decisions) else "completed",
              "requests": count, "decisions": decisions, "observations": observations, "findings": findings}
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "workflow-evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
