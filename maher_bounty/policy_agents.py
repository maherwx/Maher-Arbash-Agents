"""Native policy agents select declared cases, execute them, and review evidence."""
from pathlib import Path
from collections import Counter
from .workflow_execution import validate_manifest, execute_workflows
from .artifact_io import write_json_atomic


def policy_case_catalog(manifest):
    catalog = {}
    for category in ("access_cases", "state_cases", "workflows"):
        for case in manifest.get(category, []):
            catalog[case["id"]] = {"case_ref": case["id"], "kind": category,
                                   "case": case}
    return catalog


def run_policy_agents(manifest, scope, out_dir, *, authorized=False, agent_requests=None, transport=None):
    if not authorized:
        raise ValueError("policy agents require explicit authorization")
    validate_manifest(manifest, scope)
    catalog = policy_case_catalog(manifest)
    if len(catalog) > 100:
        raise ValueError("policy agents accept at most one hundred declared cases")
    if agent_requests is None:
        roles = {"access_cases": "access_policy_executor", "state_cases": "state_integrity_executor",
                 "workflows": "workflow_invariant_executor"}
        agent_requests = [{"agent": roles[category], "tool_requests": [{"tool": "policy-case",
                           "case_refs": [row["case_ref"] for row in catalog.values() if row["kind"] == category]}]}
                          for category in roles]
    if not isinstance(agent_requests, list) or len(agent_requests) > 120:
        raise ValueError("policy agent requests must be a bounded packet list")
    # Use the same fair role admission as shell tools. Selection references
    # declared cases only; request objects, identities and credentials cannot
    # be replaced by a model/worker packet.
    from .agent_tool_router import _request_rows
    rows = _request_rows(agent_requests, limit=20)
    chosen, admissions, owners = set(), [], {}
    for row in rows:
        references = row.get("case_refs", [])
        if row.get("tool") != "policy-case" or set(row) - {"agent", "tool", "case_refs", "reason"}:
            admissions.append({"agent": row["agent"], "status": "rejected", "reason": "unsupported_policy_request"})
            continue
        if not isinstance(references, list) or len(references) > 100:
            admissions.append({"agent": row["agent"], "status": "rejected", "reason": "case_reference_limit"})
            continue
        for reference in references:
            if not isinstance(reference, str) or reference not in catalog:
                admissions.append({"agent": row["agent"], "status": "rejected", "reason": "unknown_case_reference"})
                continue
            if reference in chosen:
                admissions.append({"agent": row["agent"], "case_ref": reference, "status": "skipped", "reason": "already_admitted"})
                continue
            chosen.add(reference)
            owners[reference] = row["agent"]
            admissions.append({"agent": row["agent"], "case_ref": reference, "status": "admitted"})
    root = Path(out_dir)
    plan = {"mode": "native_declared_policy_agents", "admissions": admissions,
            "configured_case_count": len(catalog), "selected_case_count": len(chosen),
            "tool_request_limit": 20, "model_inference_used": False,
            "case_catalog": [{"case_ref": row["case_ref"], "kind": row["kind"]} for row in catalog.values()]}
    write_json_atomic(root / "policy-agent-plan.json", plan)
    if not chosen:
        result = {"status": "not_run", "requests": 0, "findings": [], "decisions": [], "observations": []}
    else:
        selected = {**manifest}
        for category in ("access_cases", "state_cases", "workflows"):
            selected[category] = [case for case in manifest.get(category, []) if case["id"] in chosen]
        # Execute once as a combined manifest: global request/time budgets,
        # ordering, cleanup and isolated identity semantics remain shared.
        result = execute_workflows(selected, scope, root / "execution", authorized=True, transport=transport)
    analyses = []
    for decision in result["decisions"]:
        analyses.append({"case_ref": decision["id"], "requested_by": owners.get(decision["id"]),
                         "outcome": decision["status"], "phase": decision.get("phase"),
                         "requires_review": decision["status"] != "completed" or any(
                             finding.get("evidence", {}).get("case_id", finding.get("evidence", {}).get("workflow_id")) == decision["id"]
                             for finding in result["findings"])})
    reviews = []
    for finding in result["findings"]:
        evidence = finding.get("evidence", {})
        reference = evidence.get("case_id", evidence.get("workflow_id"))
        checks = evidence.get("observations", [])
        rows_bound = reference in chosen and isinstance(checks, list) and bool(checks)
        confirmed = False
        if finding.get("validated") is True and finding.get("source") == "workflow_execution" and rows_bound:
            def complete(row):
                assertions = row.get("assertions", [])
                return (not row.get("truncated") and not row.get("network_incomplete") and bool(assertions)
                        and all(assertion.get("passed") is True and assertion.get("evidence_complete") is not False
                                for assertion in assertions))
            allowed = [row for row in checks if row.get("role") == "allowed"]
            denied = [row for row in checks if row.get("role") == "denied" and row.get("identity") == evidence.get("identity")]
            required = catalog[reference]["case"].get("allowed", [])
            confirmed = (bool(required) and all(sum(row.get("identity") == identity for row in allowed) == 2 for identity in required)
                         and all(complete(row) for row in allowed) and len(denied) == 2 and all(complete(row) for row in denied))
        if finding.get("validated") is True and not confirmed:
            finding["validated"] = False
        reviews.append({"case_ref": reference, "source": finding.get("source"), "evidence_bound_to_selected_case": rows_bound,
                        "proof_level": "repeatable_declared_access_violation" if confirmed else "candidate_requires_impact_review"})
    agents = [{"agent": "declared_policy_planner", "status": "completed", "selected_cases": len(chosen)},
              {"agent": "policy_execution_coordinator", "status": result["status"], "requests": result["requests"]},
              {"agent": "policy_outcome_analyst", "status": "completed", "case_outcomes": analyses},
              {"agent": "policy_evidence_reviewer", "status": "completed", "finding_reviews": reviews}]
    summary = {**plan, "agent_results": agents, "execution": result,
               "outcome_counts": dict(Counter(row["outcome"] for row in analyses)),
               "limitations": ["native fixed policy workers, not general autonomous model inference",
                               "cases must supply application policy, identities and requests; no arbitrary shell or payloads",
                               "completed coverage is limited to selected declared cases"]}
    if chosen:
        write_json_atomic(root / "execution" / "workflow-evidence.json", result)
    write_json_atomic(root / "policy-agent-results.json", summary)
    return summary
