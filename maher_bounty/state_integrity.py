"""Explicit rejected-action policies with stable owner-observed JSON state."""
import hashlib
import json


def validate_state_cases(manifest, names):
    from .workflow_execution import _validate_expectation, _validate_pointer, _template_variables, _origin
    cases = manifest.get("state_cases", [])
    if not isinstance(cases, list) or len(cases) > 20:
        raise ValueError("state_cases must be a list of at most twenty cases")
    if cases and manifest.get("engine", "http") != "http":
        raise ValueError("state cases currently require the HTTP engine")
    requests = []
    identities = manifest["identities"]
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "owner", "actor", "observe", "resource_proof", "preserve", "action", "denial"}:
            raise ValueError("state case requires explicit identities, observation, proof, fields, action and denial")
        identifier = case["id"]
        if not isinstance(identifier, str) or not identifier or len(identifier) > 128 or identifier in names:
            raise ValueError("state case ids must be bounded unique strings")
        names.add(identifier)
        owner, actor = case["owner"], case["actor"]
        if not isinstance(owner, str) or not isinstance(actor, str) or owner == actor or owner not in identities or actor not in identities:
            raise ValueError("state case requires distinct supplied owner and actor identities")
        if _origin(identities[owner]["origin"]) != _origin(identities[actor]["origin"]):
            raise ValueError("state case identities must share an exact application origin")
        for field, allowed in (("observe", {"GET"}), ("action", {"POST", "PUT", "PATCH", "DELETE"})):
            request = case[field]
            if not isinstance(request, dict) or _template_variables(request):
                raise ValueError("state requests must be fixed supplied request objects")
            method = request.get("method", "GET")
            if not isinstance(method, str) or method.upper() not in allowed or request.get("browser"):
                raise ValueError("state request method or browser settings are unsupported")
        if "body" in case["observe"]:
            raise ValueError("state observation cannot have a body")
        _validate_expectation(case["resource_proof"])
        if not case["resource_proof"].get("json_equals") or _template_variables(case["resource_proof"]):
            raise ValueError("state observation requires a fixed resource-specific JSON proof")
        _validate_expectation(case["denial"])
        statuses = case["denial"].get("statuses", [])
        if not statuses or any(not 400 <= status < 500 for status in statuses) or _template_variables(case["denial"]):
            raise ValueError("state denial requires explicit expected 4xx statuses")
        pointers = case["preserve"]
        if not isinstance(pointers, list) or not pointers or len(pointers) > 100:
            raise ValueError("state preserve requires one to one hundred JSON Pointers")
        for pointer in pointers:
            _validate_pointer(pointer)
        if len(set(pointers)) != len(pointers):
            raise ValueError("state preserve pointers must be unique")
        requests.extend(((case["observe"], owner), (case["action"], actor)))
    return requests


def execute_state_cases(cases, send):
    # Imports occur after workflow_execution has defined its shared validators.
    from .workflow_execution import _assertions, _observation, _decode_json, _pointer_value, _json_equal
    from .burp_evidence import _safe_url
    from http.client import HTTPException
    findings, decisions, observations = [], [], []
    for case in cases:
        rows, phase = [], "baseline"
        action_requested = False
        def observe(role, repeat):
            response = send(case["owner"], case["observe"])
            checks = _assertions(response, {"statuses": [200], **case["resource_proof"]})
            row = {"identity": case["owner"], "role": role, "repeat": repeat, **_observation(response, checks)}
            rows.append(row)
            if (response["status"] != 200 or response.get("truncated") or response.get("network_incomplete")
                    or not checks or not all(check["passed"] for check in checks)):
                raise RuntimeError("state observation failed complete resource control")
            document = _decode_json(response["body"])
            snapshot, hashes, total = {}, {}, 0
            for pointer in case["preserve"]:
                value = _pointer_value(document, pointer)
                encoded = json.dumps(value, sort_keys=True, allow_nan=False, ensure_ascii=False).encode("utf-8")
                total += len(encoded)
                if len(encoded) > 65536 or total > 262144:
                    raise ValueError("selected state exceeds its evidence processing limit")
                snapshot[pointer] = value
                hashes[pointer] = hashlib.sha256(encoded).hexdigest()
            row["state_sha256"] = hashes
            return snapshot
        try:
            before = observe("baseline", 0)
            if not _json_equal(before, observe("baseline", 1)):
                raise RuntimeError("owner baseline state is unstable")
            phase = "action"
            action_requested = True
            response = send(case["actor"], case["action"])
            checks = _assertions(response, case["denial"])
            rows.append({"identity": case["actor"], "role": "action", **_observation(response, checks)})
            denial_valid = (not response.get("truncated") and not response.get("network_incomplete")
                            and bool(checks) and all(check["passed"] for check in checks))
            # Inspect owner state even if the response violates the declared
            # denial. The action is never retried; no implicit rollback occurs.
            phase = "post_action"
            after = observe("post_action", 0)
            if not _json_equal(after, observe("post_action", 1)):
                raise RuntimeError("post-action state is unstable")
            changed = [pointer for pointer in case["preserve"] if not _json_equal(before[pointer], after[pointer])]
            if not denial_valid:
                decisions.append({"id": case["id"], "status": "inconclusive", "phase": "action",
                                  "reason": "declared_denial_not_established", "state_change_observed": bool(changed),
                                  "action_requested": True})
            else:
                decisions.append({"id": case["id"], "status": "completed", "changed_fields": changed,
                                  "action_requested": True})
                if changed:
                    findings.append({"source": "state_integrity", "title": f"Rejected action changed protected state: {case['id']}",
                        "severity": "medium", "validated": False, "target": _safe_url(case["action"]["url"]),
                        "evidence": {"case_id": case["id"], "owner": case["owner"], "actor": case["actor"],
                                     "changed_fields": changed, "observations": list(rows)},
                        "basis": "declared denied action with stable before/after owner state; concurrent causes and impact require review"})
        except (OSError, RuntimeError, ValueError, KeyError, IndexError, TypeError, RecursionError, HTTPException) as error:
            decisions.append({"id": case["id"], "status": "inconclusive", "phase": phase,
                              "error_type": type(error).__name__, "action_requested": action_requested})
        observations.append({"id": case["id"], "observations": rows})
    return {"findings": findings, "decisions": decisions, "observations": observations}
