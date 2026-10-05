"""Correlate source declarations with existing scoped traffic, without requests."""
import re
from urllib.parse import urlparse
from .scope_policy import filter_in_scope_urls


METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _path_pattern(path):
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 300:
        return None, False
    parts, templated = [], False
    for segment in path.split("/"):
        if re.fullmatch(r":[A-Za-z_]\w*|\{[A-Za-z_]\w*\}|<[A-Za-z_]\w*>", segment):
            parts.append("[^/]+")
            templated = True
        elif re.fullmatch(r"<int:[A-Za-z_]\w*>", segment):
            parts.append("[0-9]+")
            templated = True
        elif any(value in segment for value in ("{", "}", "<", ">", ":", "*")):
            return None, False
        else:
            parts.append(re.escape(segment))
    return re.compile("/".join(parts)), templated


def correlate_source_traffic(source_review, traffic_evidence, target_references, scope):
    structure = source_review.get("source_structure", {})
    routes = structure.get("route_declarations", []) if isinstance(structure, dict) else []
    records = traffic_evidence.get("records", []) if isinstance(traffic_evidence, dict) else []
    routes = routes if isinstance(routes, list) else []
    records = records if isinstance(records, list) else []
    rows, matched = [], set()
    valid_traffic = []
    for record in records[:500]:
        if not isinstance(record, dict):
            continue
        reference = record.get("target_ref")
        if not isinstance(reference, str):
            continue
        url = target_references.get(reference)
        if not isinstance(url, str):
            continue
        allowed, _ = filter_in_scope_urls([url], scope)
        if not allowed:
            continue
        parsed = urlparse(url)
        method = record.get("method")
        if parsed.username or parsed.password or not isinstance(method, str) or method not in METHODS or len(parsed.path) > 4096:
            continue
        valid_traffic.append((reference, method, parsed.path or "/"))
    skipped_patterns = 0
    truncated = len(routes) > 200 or len(records) > 500
    for index, route in enumerate(routes[:200]):
        if not isinstance(route, dict):
            continue
        pattern, templated = _path_pattern(route.get("declared_path"))
        if pattern is None:
            skipped_patterns += 1
            continue
        method = route.get("method")
        if not isinstance(method, str) or method not in METHODS | {"unspecified"}:
            continue
        references = sorted({reference for reference, observed_method, path in valid_traffic
            if (method == "unspecified" or observed_method == method) and pattern.fullmatch(path)})
        if not references:
            continue
        matched.add(index)
        rows.append({"file": route.get("file"), "file_sha256": route.get("file_sha256"),
                     "declaration_line": route.get("line"), "declared_path": route["declared_path"],
                     "declared_method": method, "traffic_target_refs": references,
                     "match_kind": "segment_template" if templated else "exact_path",
                     "method_verified": method != "unspecified",
                     "candidate_lines": route.get("candidate_lines", []),
                     "source_runtime_identity_verified": False, "vulnerability_validated": False})
    return {"mode": "source_to_scoped_traffic_correspondence", "correlations": rows,
            "static_artifact_generation": source_review.get("artifact_generation"),
            "matched_declaration_count": len(matched), "observed_traffic_count": len(valid_traffic),
            "unmatched_declaration_count": max(0, len(routes[:200]) - len(matched)),
            "unsupported_route_pattern_count": skipped_patterns, "truncated": truncated,
            "network_requests_made": 0, "network_scope_expanded": False,
            "limitations": ["path/method correspondence does not prove deployment identity, reachability or exploitation",
                            "runtime prefixes, wrappers, regex routes and multi-segment converters are not inferred",
                            "only supplied exact target references revalidated against scope are considered",
                            "no query/header/body values, credentials or new target URLs are generated"]}
