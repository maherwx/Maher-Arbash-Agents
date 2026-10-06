"""Bounded local OpenAPI 3 JSON review; no fetching or request generation."""
import hashlib
import json
import re
from pathlib import Path
from collections import Counter
from .artifact_io import write_json_atomic
from .execution_journal import _unique_fields, _invalid_constant


class ContractInputError(ValueError):
    pass


def _label(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.{}:/-]{1,256}", value) else None


def review_api_contract(path, out_dir=None):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("size limit")
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_fields,
                              parse_constant=_invalid_constant)
        if not isinstance(document, dict) or not re.fullmatch(r"3\.(0|1)\.\d+", str(document.get("openapi", ""))):
            raise ValueError("unsupported version")
        # JSON exponent overflow must not silently become infinity. Strict
        # serialization also rejects malformed non-finite values after decode.
        json.dumps(document, allow_nan=False)
    except (OSError, ValueError, TypeError, RecursionError) as error:
        raise ContractInputError("local contract requires bounded finite OpenAPI 3.0/3.1 JSON") from error
    gaps = Counter()
    visits = 0
    def resolve(value):
        nonlocal visits
        seen = set()
        for _ in range(16):
            visits += 1
            if visits > 10000:
                gaps["reference_work_budget"] += 1
                return None
            if not isinstance(value, dict):
                gaps["invalid_object"] += 1
                return None
            if "$ref" not in value:
                return value
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                gaps["external_reference_not_loaded"] += 1
                return None
            if ref in seen or re.search(r"~(?![01])", ref) or "%" in ref:
                gaps["cyclic_or_unsupported_reference"] += 1
                return None
            if len(value) > 1:
                gaps["reference_siblings_not_merged"] += 1
                return None
            seen.add(ref)
            value = document
            for segment in ref[2:].split("/"):
                key = segment.replace("~1", "/").replace("~0", "~")
                if not isinstance(value, dict) or key not in value:
                    gaps["unresolved_reference"] += 1
                    return None
                value = value[key]
        gaps["reference_depth_limit"] += 1
        return None
    def properties(schema):
        schema = resolve(schema)
        if schema is None:
            return []
        if any(key in schema for key in ("allOf", "oneOf", "anyOf", "if", "then", "else")):
            gaps["composition_not_expanded"] += 1
            return []
        values = schema.get("properties", {})
        if not isinstance(values, dict):
            gaps["invalid_properties"] += 1
            return []
        if len(values) > 100:
            gaps["property_limit"] += 1
        rows = []
        for name, value in list(values.items())[:100]:
            value = resolve(value)
            if value is not None and _label(name):
                rows.append({"name": name, "type": value.get("type") if value.get("type") in
                    ("string", "number", "integer", "boolean", "object", "array", "null") else "unspecified",
                    "read_only": value.get("readOnly") is True, "write_only": value.get("writeOnly") is True})
        return rows
    schemes = document.get("components", {}).get("securitySchemes", {}) if isinstance(document.get("components"), dict) else {}
    if not isinstance(schemes, dict):
        schemes = {}
        gaps["invalid_security_schemes"] += 1
    def security(value, source):
        if not isinstance(value, list) or len(value) > 20:
            gaps["invalid_security_requirement"] += 1
            return {"mode": "unknown", "source": source, "alternatives": []}
        alternatives, anonymous = [], not value
        for alternative in value:
            if not isinstance(alternative, dict) or len(alternative) > 20:
                gaps["invalid_security_requirement"] += 1
                return {"mode": "unknown", "source": source, "alternatives": []}
            anonymous = anonymous or not alternative
            group = []
            for name, scopes in alternative.items():
                if (not _label(name) or not isinstance(scopes, list) or len(scopes) > 100
                        or any(not _label(scope) for scope in scopes)):
                    gaps["invalid_security_requirement"] += 1
                    return {"mode": "unknown", "source": source, "alternatives": []}
                scheme = resolve(schemes[name]) if name in schemes else None
                if scheme is None:
                    gaps["unresolved_security_scheme"] += 1
                kind = scheme.get("type") if scheme else None
                group.append({"scheme": name, "type": kind if kind in ("apiKey", "http", "oauth2", "openIdConnect", "mutualTLS") else "unknown",
                              "scopes": sorted(set(scopes))})
            alternatives.append(sorted(group, key=lambda item: item["scheme"]))
        return {"mode": "no_security_declared" if source == "undeclared" else "anonymous_alternative" if anonymous else "declared_authenticated",
                "source": source, "alternatives": sorted(alternatives, key=lambda group: json.dumps(group, sort_keys=True))}
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ContractInputError("local contract paths must be an object")
    operations = []
    output_bytes, output_truncated = 0, False
    for route, item in list(paths.items())[:500]:
        if output_truncated:
            break
        if not _label(route) or not route.startswith("/"):
            gaps["unsupported_path"] += 1
            continue
        item = resolve(item)
        if item is None:
            continue
        for method in ("get", "head", "options", "post", "put", "patch", "delete", "trace"):
            if method not in item:
                continue
            if len(operations) >= 500:
                gaps["operation_limit"] += 1
                break
            operation = resolve(item[method])
            if operation is None:
                continue
            source = "operation" if "security" in operation else "global" if "security" in document else "undeclared"
            auth = security(operation.get("security", document.get("security", [])), source)
            parameters = {}
            for parameter_list in (item.get("parameters", []), operation.get("parameters", [])):
                if not isinstance(parameter_list, list):
                    gaps["invalid_parameters"] += 1
                    continue
                if len(parameter_list) > 100:
                    gaps["parameter_limit"] += 1
                for parameter in parameter_list[:100]:
                    parameter = resolve(parameter)
                    if parameter and _label(parameter.get("name")) and parameter.get("in") in ("path", "query", "header", "cookie"):
                        key = (parameter["name"], parameter["in"])
                        parameters[key] = {"name": parameter["name"], "location": parameter["in"],
                                           "required": parameter.get("required") is True}
                    else:
                        gaps["unsupported_parameter"] += 1
            fields = []
            if "requestBody" in operation:
                body = resolve(operation["requestBody"])
                content = body.get("content", {}) if body else {}
                if isinstance(content, dict):
                    json_body = content.get("application/json", {})
                    if isinstance(json_body, dict) and "schema" in json_body:
                        fields = properties(json_body["schema"])
            questions = []
            if any(parameter["location"] == "path" for parameter in parameters.values()):
                questions.append("object authorization: supply owned resource and distinct test identity")
            if any(field["read_only"] for field in fields) and method in {"post", "put", "patch"}:
                questions.append("property authorization: readOnly fields require explicit mutation/state policy")
            if method in {"post", "put", "patch", "delete"}:
                questions.append("rejected-operation state integrity and prerequisite enforcement")
            row = {"path": route, "method": method.upper(), "operation_id": _label(operation.get("operationId")),
                               "security": auth, "parameters": list(parameters.values()), "request_fields": fields,
                               "proposed_checks": questions, "runtime_verified": False}
            row_bytes = len(json.dumps(row, ensure_ascii=False).encode("utf-8"))
            if output_bytes + row_bytes > 2 * 1024 * 1024:
                gaps["operation_output_budget"] += 1
                output_truncated = True
                break
            output_bytes += row_bytes
            operations.append(row)
    if len(paths) > 500:
        gaps["path_limit"] += 1
    families = {}
    for operation in operations:
        family = re.sub(r"/v[0-9]+(?=/|$)", "/{version}", operation["path"])
        families.setdefault((family, operation["method"]), []).append(operation)
    differences = []
    for (family, method), rows in families.items():
        signatures = {json.dumps({key: row["security"][key] for key in ("mode", "alternatives")}, sort_keys=True) for row in rows}
        if len(rows) > 1 and len(signatures) > 1:
            differences.append({"family": family, "method": method, "paths": [row["path"] for row in rows],
                                "review": "declared security differs across version routes; deployment policy requires verification"})
    result = {"mode": "local_openapi_contract_review", "contract_sha256": hashlib.sha256(raw).hexdigest(),
              "operation_count": len(operations), "operations": operations, "version_security_differences": differences,
              "coverage_gaps": dict(gaps), "status": "partial" if gaps else "completed", "runtime_verified": False,
              "limitations": ["contract declarations are not deployed authorization behavior",
                              "local JSON references only; composition and schema validation are incomplete",
                              "no servers, credentials, defaults, examples or descriptions copied; no requests scheduled"]}
    if out_dir is not None:
        write_json_atomic(Path(out_dir) / "api-contract-review.json", result)
    return result
