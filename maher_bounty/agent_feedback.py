"""Bounded local execution feedback; deterministic coordination needs no model."""
from pathlib import Path
from .agent_tool_router import run_agent_tool_requests, build_local_tool_requests, _coverage_key
from .scope_policy import filter_in_scope_urls


def run_agent_tool_feedback(results, known_urls, out_dir, *, scope, active_testing=None,
                            tool_plan=None, target_references=None, max_rounds=3):
    if type(max_rounds) is not int or not 1 <= max_rounds <= 3:
        raise ValueError("agent feedback requires one to three rounds")
    known, rejected = filter_in_scope_urls(known_urls, scope)
    known = list(dict.fromkeys(known))
    initial = set(known)
    attempted = set()
    context = dict(active_testing or {})
    context["runs"] = list(context.get("runs", []))
    aggregate = {"mode": "bounded_local_execution_feedback", "request_count": 0,
                 "runs": [], "findings": [], "decisions": [], "rounds": [],
                 "new_in_scope_urls": [], "rejected_inventory_url_count": len(rejected)}
    pending = results
    stop = "round_limit"
    for index in range(max_rounds):
        submitted = []
        for row in pending:
            if not isinstance(row, dict) or not isinstance(row.get("tool_requests", []), list):
                continue
            requests = []
            for request in row.get("tool_requests", []):
                if not isinstance(request, dict):
                    continue
                tool = request.get("tool", "")
                targets = request.get("targets", [])
                if not isinstance(tool, str) or not isinstance(targets, list):
                    continue
                tool = tool.strip().lower()
                fresh_targets = []
                for target in targets:
                    if not isinstance(target, str):
                        continue
                    resolved = (target_references or {}).get(target, target)
                    key = (tool, _coverage_key(tool, resolved))
                    if key not in attempted:
                        attempted.add(key)
                        fresh_targets.append(target)
                if fresh_targets:
                    requests.append({**request, "targets": fresh_targets})
            if requests:
                submitted.append({**row, "tool_requests": requests})
        if not submitted:
            stop = "no_unattempted_requests"
            break
        summary = run_agent_tool_requests(submitted, known, Path(out_dir) / f"round-{index + 1}",
                                          scope=scope, active_testing=context, tool_plan=tool_plan,
                                          target_references=target_references)
        for key in ("runs", "findings", "decisions"):
            aggregate[key].extend(summary.get(key, []))
        aggregate["request_count"] += summary.get("request_count", 0)
        context["runs"].extend(summary.get("runs", []))
        allowed, _ = filter_in_scope_urls(summary.get("new_in_scope_urls", []), scope)
        fresh = [url for url in dict.fromkeys(allowed) if url not in known]
        # Bound newly admitted routes across all rounds, not just each crawler.
        fresh = fresh[:max(0, 30 - len(aggregate["new_in_scope_urls"]))]
        known.extend(fresh)
        aggregate["new_in_scope_urls"].extend(fresh)
        aggregate["rounds"].append({"round": index + 1, "new_url_count": len(fresh),
                                    "run_count": len(summary.get("runs", [])),
                                    "finding_count": len(summary.get("findings", []))})
        if not fresh:
            stop = "no_new_in_scope_evidence"
            break
        pending = build_local_tool_requests(known, scope=scope, active_testing=context,
                                           tool_plan=tool_plan)["agent_results"]
    aggregate["stop_reason"] = stop
    aggregate["known_in_scope_url_count"] = len(initial | set(aggregate["new_in_scope_urls"]))
    return aggregate
