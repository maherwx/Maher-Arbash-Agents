"""Bounded local execution feedback; deterministic coordination needs no model."""
from pathlib import Path
from .agent_tool_router import run_agent_tool_requests, build_local_tool_requests, _coverage_key
from .scope_policy import filter_in_scope_urls


def run_agent_tool_feedback(results, known_urls, out_dir, *, scope, active_testing=None,
                            tool_plan=None, target_references=None, max_rounds=3, reviewer=None):
    if type(max_rounds) is not int or not 1 <= max_rounds <= 3:
        raise ValueError("agent feedback requires one to three rounds")
    if reviewer is not None and not callable(reviewer):
        raise ValueError("execution reviewer must be callable")
    known, rejected = filter_in_scope_urls(known_urls, scope)
    known = list(dict.fromkeys(known))
    initial = set(known)
    attempted = set()
    context = dict(active_testing or {})
    context["runs"] = list(context.get("runs", []))
    aggregate = {"mode": "bounded_local_execution_feedback", "request_count": 0,
                 "runs": [], "findings": [], "decisions": [], "rounds": [],
                 "new_in_scope_urls": [], "rejected_inventory_url_count": len(rejected)}
    if reviewer is not None:
        aggregate["review_rounds"] = []
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
                if not isinstance(tool, str):
                    continue
                tool = tool.strip().lower()
                if tool in {"zap", "zaproxy", "zap.sh"}:
                    tool = "zap-baseline.py"
                targets = [targets] if isinstance(targets, str) else list(targets) if isinstance(targets, list) else []
                refs = request.get("target_refs", [])
                refs = [refs] if isinstance(refs, str) else refs if isinstance(refs, list) else []
                unknown = 0
                for ref in refs:
                    if not isinstance(ref, str):
                        continue
                    resolved = (target_references or {}).get(ref)
                    if isinstance(resolved, str) and resolved:
                        targets.append(resolved)
                    else:
                        unknown += 1
                if unknown:
                    aggregate["decisions"].append({"agent": row.get("agent"), "tool": tool,
                                                   "status": "filtered", "unknown_target_ref_count": unknown})
                fresh_targets = []
                for target in targets:
                    if not isinstance(target, str):
                        continue
                    key = (tool, _coverage_key(tool, target))
                    if key not in attempted:
                        attempted.add(key)
                        fresh_targets.append(target)
                if fresh_targets:
                    # References are resolved once before attempt deduplication.
                    requests.append({**request, "tool": tool, "targets": fresh_targets, "target_refs": []})
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
        reviews = []
        if reviewer is not None:
            packet = {"round": index + 1, "can_schedule_next_round": index + 1 < max_rounds,
                      "known_urls": list(known), "new_in_scope_urls": list(fresh),
                      "runs": list(aggregate["runs"]), "findings": list(aggregate["findings"]),
                      "decisions": list(aggregate["decisions"])}
            try:
                response = reviewer(packet)
                if not isinstance(response, list):
                    raise ValueError("execution review requires agent results")
                reviews = [row for row in response[:8] if isinstance(row, dict)]
                aggregate["review_rounds"].append({"round": index + 1, "agent_count": len(reviews),
                    "requested_batches": sum(len(row.get("tool_requests", [])) for row in reviews
                                             if isinstance(row.get("tool_requests", []), list))})
            except Exception as exc:
                aggregate["review_rounds"].append({"round": index + 1, "status": "error",
                                                   "error_type": type(exc).__name__})
        has_requests = any(bool(row.get("tool_requests")) for row in reviews
                           if isinstance(row.get("tool_requests"), list))
        if not fresh and not has_requests:
            stop = "no_new_in_scope_evidence"
            break
        pending = [*reviews, *build_local_tool_requests(known, scope=scope, active_testing=context,
                                                       tool_plan=tool_plan)["agent_results"]]
    aggregate["stop_reason"] = stop
    aggregate["known_in_scope_url_count"] = len(initial | set(aggregate["new_in_scope_urls"]))
    return aggregate
