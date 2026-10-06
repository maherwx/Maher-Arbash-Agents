"""Bound supplied GraphQL queries used by the HTTP access-policy executor.

Syntax checks cannot establish resolver side effects or schema validity.
No schema discovery, request generation, or external service is used here.
"""
from __future__ import annotations

import hashlib
import json
import re


def graphql_request_metadata(request):
    """Validate a supplied JSON POST query and return non-content provenance."""
    if not isinstance(request, dict) or not isinstance(request.get("method", "GET"), str) or request.get("method", "GET").upper() != "POST":
        raise ValueError("GraphQL access cases require POST")
    body = request.get("body")
    if not isinstance(body, dict) or set(body) - {"query", "variables", "operationName"}:
        raise ValueError("GraphQL requires one query body; batches/extensions are unsupported")
    query = body.get("query")
    if not isinstance(query, str) or not query.strip() or len(query.encode("utf-8")) > 65536:
        raise ValueError("GraphQL query must be nonempty and at most 64 KiB")
    variables = body.get("variables", {})
    if not isinstance(variables, dict) or any(not isinstance(key, str) or not
            re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", key) for key in variables):
        raise ValueError("GraphQL variables must be an object with valid variable names")
    try:
        encoded = json.dumps(body, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("GraphQL body requires finite JSON values") from exc
    if len(encoded.encode("utf-8")) > 131072:
        raise ValueError("GraphQL request body exceeds 128 KiB")
    operation_name = body.get("operationName")
    if operation_name is not None and (not isinstance(operation_name, str)
                                      or not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", operation_name)):
        raise ValueError("invalid GraphQL operationName")
    headers = request.get("headers", {})
    if not isinstance(headers, dict) or any(not isinstance(key, str) for key in headers):
        raise ValueError("GraphQL headers must be a string-keyed object")
    content_types = [value for key, value in headers.items() if key.lower() == "content-type"]
    if len(content_types) > 1 or any(not isinstance(value, str) or
            value.split(";", 1)[0].strip().lower() != "application/json" for value in content_types):
        raise ValueError("GraphQL requires application/json Content-Type")
    try:
        from graphql import GraphQLError, OperationType, parse
    except ImportError as exc:
        raise ValueError("GraphQL cases require the installed local graphql extra") from exc
    try:
        document = parse(query, no_location=True, max_tokens=5000)
    except (GraphQLError, RecursionError) as exc:
        # Do not propagate parser diagnostics containing supplied query values.
        raise ValueError("invalid or excessive GraphQL query syntax") from exc
    operations, fragments = [], {}
    for definition in document.definitions:
        if definition.kind == "operation_definition":
            if definition.operation != OperationType.QUERY:
                raise ValueError("GraphQL access cases cannot contain mutations/subscriptions")
            operations.append(definition)
        elif definition.kind == "fragment_definition":
            name = definition.name.value
            if name in fragments:
                raise ValueError("duplicate GraphQL fragment")
            fragments[name] = definition
        else:
            raise ValueError("GraphQL access cases require executable query definitions")
    if not operations or len(operations) > 10 or len(fragments) > 100:
        raise ValueError("GraphQL definition limit exceeded")
    names = [operation.name.value if operation.name else None for operation in operations]
    if len(set(names)) != len(names) or (len(operations) > 1 and None in names):
        raise ValueError("GraphQL operations require unique names; anonymous queries must stand alone")
    if operation_name is None:
        if len(operations) != 1:
            raise ValueError("multiple GraphQL operations require operationName")
        selected = operations[0]
    elif operation_name not in names:
        raise ValueError("unknown GraphQL operationName")
    else:
        selected = operations[names.index(operation_name)]
    visits, max_depth, fields = 0, 0, 0

    def walk(selection_set, depth, active):
        nonlocal visits, max_depth, fields
        if depth > 12:
            raise ValueError("GraphQL selection depth exceeds 12")
        max_depth = max(max_depth, depth)
        for selection in selection_set.selections:
            visits += 1
            if visits > 1000:
                raise ValueError("GraphQL expanded selection limit exceeded")
            if selection.kind == "field":
                fields += 1
                if selection.selection_set:
                    walk(selection.selection_set, depth + 1, active)
            elif selection.kind == "inline_fragment":
                walk(selection.selection_set, depth + 1, active)
            elif selection.kind == "fragment_spread":
                name = selection.name.value
                if name not in fragments or name in active:
                    raise ValueError("unknown or cyclic GraphQL fragment")
                walk(fragments[name].selection_set, depth + 1, active | {name})
            else:
                raise ValueError("unsupported GraphQL selection")

    # Include unused definitions to reject hidden cycles and excessive expansion.
    for operation in operations:
        walk(operation.selection_set, 1, set())
    for name, fragment in fragments.items():
        walk(fragment.selection_set, 1, {name})
    return {"protocol": "graphql", "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "request_body_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            "operation_named": selected.name is not None,
            "expanded_definition_fields": fields, "max_selection_depth": max_depth}


def validate_graphql_case(case, engine):
    if engine != "http":
        raise ValueError("GraphQL access cases require engine=http")
    if "negative_control" in case:
        raise ValueError("GraphQL negative controls are not supported")
    request = case.get("request", {})
    if not isinstance(request, dict):
        raise ValueError("GraphQL request must be an object")
    if request.get("browser"):
        raise ValueError("GraphQL access cases cannot contain browser settings")
    proof = case.get("proof", {}).get("json_equals", {})
    if "statuses" in case.get("proof", {}) and case["proof"]["statuses"] != [200]:
        raise ValueError("GraphQL positive access proofs require HTTP 200")
    if not proof or any(not pointer.startswith("/data/") or pointer == "/data/"
                        or expected is None or isinstance(expected, (dict, list))
                        for pointer, expected in proof.items()):
        raise ValueError("GraphQL proof requires non-null scalar json_equals fields below /data/")
    return graphql_request_metadata(request)


def graphql_envelope_valid(document):
    """Allow partial data with errors, but do not treat non-GraphQL JSON as denial."""
    if not isinstance(document, dict):
        return False
    data_valid = "data" in document and (document["data"] is None or isinstance(document["data"], dict))
    errors = document.get("errors")
    errors_valid = (isinstance(errors, list) and bool(errors)
                    and all(isinstance(item, dict) and isinstance(item.get("message"), str) for item in errors))
    return ((data_valid or errors_valid) and ("data" not in document or data_valid)
            and ("errors" not in document or errors_valid))
