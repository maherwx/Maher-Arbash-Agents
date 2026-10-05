"""Bounded local execution feedback; deterministic coordination needs no model."""
from pathlib import Path
import hashlib
from .agent_tool_router import run_agent_tool_requests, build_local_tool_requests, _coverage_key
from .scope_policy import filter_in_scope_urls
from .execution_journal import ExecutionJournal


def run_agent_tool_feedback(results, known_urls, out_dir, *, scope, active_testing=None,
                            tool_plan=None, target_references=None, max_rounds=3, reviewer=None,
                            checkpoint_path=None, resume=False, checkpoint_context=None):
    options = dict(scope=scope, active_testing=active_testing, tool_plan=tool_plan,
                   target_references=target_references, max_rounds=max_rounds, reviewer=reviewer)
    if checkpoint_path is None:
        if resume:
            raise ValueError("execution resume requires a checkpoint path")
        return _run_agent_tool_feedback(results, known_urls, out_dir, **options)
    # Bind all supplied execution inputs. A checkpoint cannot expand scope or
    # silently reuse evidence under different identities, tools or base coverage.
    binding = {"scope": scope, "known_urls": known_urls, "active_testing": active_testing,
               "tool_plan": tool_plan, "target_references": target_references,
               "max_rounds": max_rounds, "model_review_enabled": reviewer is not None,
               "execution_policy": checkpoint_context,
               "out_dir": str(Path(out_dir).resolve())}
    with ExecutionJournal(checkpoint_path, binding) as journal:
        restored = journal.load() if resume else None
        return _run_agent_tool_feedback(results, known_urls, out_dir, journal=journal,
                                        restored=restored, **options)


def _run_agent_tool_feedback(results, known_urls, out_dir, *, scope, active_testing=None,
                             tool_plan=None, target_references=None, max_rounds=3,
                             reviewer=None, journal=None, restored=None):
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
                 "remaining_deferred_request_count": 0,
                 "admitted_attempts": [],
                 "new_in_scope_urls": [], "rejected_inventory_url_count": len(rejected)}
    if reviewer is not None:
        aggregate["review_rounds"] = []
    pending = results
    stop = "round_limit"
    start = 0
    if restored is not None:
        start = restored.get("next_round")
        if type(start) is not int or not 0 <= start <= max_rounds:
            raise ValueError("execution journal round is invalid")
        if not all(isinstance(restored.get(key), list) for key in ("known", "attempted", "pending")):
            raise ValueError("execution journal request state is invalid")
        saved_aggregate = restored.get("aggregate")
        if not isinstance(saved_aggregate, dict) or not isinstance(restored.get("context"), dict):
            raise ValueError("execution journal evidence state is invalid")
        for key in ("runs", "findings", "decisions", "rounds", "new_in_scope_urls"):
            if not isinstance(saved_aggregate.get(key), list):
                raise ValueError("execution journal evidence collection is invalid")
        if not isinstance(restored["context"].get("runs"), list):
            raise ValueError("execution journal coverage history is invalid")
        if type(saved_aggregate.get("request_count")) is not int or saved_aggregate["request_count"] < 0:
            raise ValueError("execution journal request count is invalid")
        if reviewer is not None and not isinstance(saved_aggregate.get("review_rounds"), list):
            raise ValueError("execution journal review history is invalid")
        checked, rejected_saved = filter_in_scope_urls(restored["known"], scope)
        if rejected_saved or set(known) - set(checked):
            raise ValueError("execution journal target inventory is invalid")
        known = list(dict.fromkeys(checked))
        attempted = set()
        for pair in restored["attempted"]:
            if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(value, str) for value in pair):
                raise ValueError("execution journal attempt ledger is invalid")
            attempted.add(tuple(pair))
        context, aggregate, pending = restored["context"], saved_aggregate, restored["pending"]
        if restored.get("finished") is True:
            return aggregate

    aggregate.setdefault("admitted_attempts", [])
    if not isinstance(aggregate["admitted_attempts"], list):
        raise ValueError("execution journal admission evidence is invalid")

    def save(phase, next_round, finished=False):
        if journal is not None:
            journal.save(phase, {"next_round": next_round, "known": known,
                "attempted": sorted(attempted), "context": context, "aggregate": aggregate,
                "pending": pending, "finished": finished})

    for index in range(start, max_rounds):
        submitted = []
        proposed = set()
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
                    if key not in attempted and key not in proposed:
                        proposed.add(key)
                        fresh_targets.append(target)
                if fresh_targets:
                    # References are resolved once before attempt deduplication.
                    requests.append({**request, "tool": tool, "targets": fresh_targets, "target_refs": []})
            if requests:
                submitted.append({**row, "tool_requests": requests})
        if not submitted:
            stop = "no_unattempted_requests"
            aggregate["remaining_deferred_request_count"] = 0
            break
        save("running_round", index)
        summary = run_agent_tool_requests(submitted, known, Path(out_dir) / f"round-{index + 1}",
                                          scope=scope, active_testing=context, tool_plan=tool_plan,
                                          target_references=target_references)
        # Only admitted execution counts as an attempt. A request beyond a
        # round's budget must remain eligible for a later round.
        admitted = summary.get("attempted_targets")
        if isinstance(admitted, list):
            for item in admitted:
                if isinstance(item, dict) and isinstance(item.get("tool"), str) and isinstance(item.get("target"), str):
                    attempted.add((item["tool"], _coverage_key(item["tool"], item["target"])))
                    aggregate["admitted_attempts"].append({"round": index + 1, "tool": item["tool"],
                        "coverage_sha256": hashlib.sha256(_coverage_key(item["tool"], item["target"]).encode("utf-8")).hexdigest()})
        else:
            # Compatibility for older router implementations without admission metadata.
            attempted.update(proposed)
        deferred = summary.get("deferred_requests", [])
        deferred = [row for row in deferred if isinstance(row, dict)] if isinstance(deferred, list) else []
        deferred_count = sum(len(row["tool_requests"]) for row in deferred
                             if isinstance(row.get("tool_requests"), list))
        aggregate["remaining_deferred_request_count"] = deferred_count
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
                                    "deferred_request_count": deferred_count,
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
        if not fresh and not has_requests and not deferred:
            stop = "no_new_in_scope_evidence"
            break
        pending = [*deferred, *reviews, *build_local_tool_requests(known, scope=scope, active_testing=context,
                                                       tool_plan=tool_plan)["agent_results"]]
        save("completed_round", index + 1)
    aggregate["stop_reason"] = stop
    aggregate["known_in_scope_url_count"] = len(initial | set(aggregate["new_in_scope_urls"]))
    save("completed_round", max_rounds, finished=True)
    return aggregate
