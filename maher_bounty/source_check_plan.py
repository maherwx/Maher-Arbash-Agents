"""Source-guided requests for existing fixed local verification tools."""
import hashlib
from urllib.parse import urlparse
from .agent_tool_router import _coverage_key, _prior_coverage
from .scope_policy import filter_in_scope_urls


def build_source_check_plan(source_review, traffic_evidence, references, known_urls, scope,
                            active_testing=None, tool_plan=None):
    allowed, _ = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    covered = _prior_coverage(active_testing or {}, known, tool_plan)
    methods = {}
    for record in traffic_evidence.get("records", [])[:500]:
        if isinstance(record, dict) and isinstance(record.get("target_ref"), str):
            methods.setdefault(record["target_ref"], set()).add(str(record.get("method", "")))
    candidates = {}
    for row in source_review.get("findings", []):
        if not isinstance(row, dict) or not isinstance(row.get("file"), str) or type(row.get("line")) is not int:
            continue
        key = (row["file"], row["line"])
        if key not in candidates or row.get("cwe") == "CWE-79":
            candidates[key] = row
    tasks, requests, seen = [], [], set()
    correspondence = source_review.get("traffic_correspondence", {})
    for match in correspondence.get("correlations", [])[:200]:
        if not isinstance(match, dict) or not isinstance(match.get("file"), str):
            continue
        for line in match.get("candidate_lines", [])[:200]:
            if type(line) is not int:
                continue
            candidate = candidates.get((match.get("file"), line))
            if not candidate or candidate.get("file_sha256") != match.get("file_sha256"):
                continue
            for reference in match.get("traffic_target_refs", [])[:500]:
                url = references.get(reference) if isinstance(reference, str) else None
                if not isinstance(url, str) or url not in known:
                    continue
                # Existing checks take URLs, not captured bodies or identities.
                # Do not replay a POST/PUT workflow as an invented GET.
                if "GET" not in methods.get(reference, set()):
                    continue
                tools = ["nuclei"]
                if candidate.get("cwe") == "CWE-79" and urlparse(url).query:
                    tools = ["browser-xss", "dalfox", "nuclei"]
                for tool in tools:
                    key = (tool, reference, match["file"], line)
                    if key in seen:
                        continue
                    seen.add(key)
                    task_id = hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:20]
                    status = "covered_by_prior_attempt" if _coverage_key(tool, url) in covered[tool] else "requested"
                    tasks.append({"task_id": task_id, "file": match["file"], "file_sha256": match["file_sha256"],
                                  "line": line, "cwe": candidate.get("cwe"), "target_ref": reference,
                                  "tool": tool, "status": status, "candidate_validated": False})
                    if status == "requested":
                        requests.append({"agent": "local_source_check_coordinator", "tool_requests": [{
                            "tool": tool, "target_refs": [reference],
                            "reason": f"source-correlated observed GET; task {task_id}; candidate still unverified"}]})
                    if len(tasks) >= 100:
                        return _result(tasks, requests, True)
    return _result(tasks, requests, False)


def _result(tasks, requests, truncated):
    # One role packet avoids overflowing the router's packet limit. Its twenty
    # distinct request slots aggregate target references by tool.
    groups = {}
    for row in requests:
        request = row["tool_requests"][0]
        groups.setdefault(request["tool"], set()).update(request["target_refs"])
    packets = [{"agent": "local_source_check_coordinator", "tool_requests": [
        {"tool": tool, "target_refs": sorted(refs),
         "reason": "source-correlated observed GET checks; source task ledger contains provenance"}
        for tool, refs in groups.items()]}] if groups else []
    return {"mode": "source_guided_existing_tool_checks", "tasks": tasks, "agent_results": packets,
            "task_count": len(tasks), "truncated": truncated,
            "limitations": ["Nuclei is a complementary template pass, not proof of a particular source defect",
                            "browser-xss verifies only its supported query context; no authenticated body replay",
                            "prior coverage includes failed, blocked and missing attempts; it is not success"]}


def audit_source_checks(plan, summary, references):
    attempts = {(row.get("tool"), row.get("coverage_sha256")) for row in summary.get("admitted_attempts", [])
                if isinstance(row, dict)}
    tasks = []
    for task in plan.get("tasks", []):
        row = dict(task)
        url = references.get(task["target_ref"])
        if task["status"] == "requested" and isinstance(url, str):
            digest = hashlib.sha256(_coverage_key(task["tool"], url).encode("utf-8")).hexdigest()
            row["status"] = "admitted_attempt" if (task["tool"], digest) in attempts else "not_admitted"
        tasks.append(row)
    return {"mode": "source_check_admission_audit", "tasks": tasks,
            "admitted_task_count": sum(row["status"] == "admitted_attempt" for row in tasks),
            "candidate_validation_changed": False,
            "limitations": ["admission is an attempt, not tool success or proof of source exploitability",
                            "actual run statuses and runtime findings remain in the normal execution report"]}
