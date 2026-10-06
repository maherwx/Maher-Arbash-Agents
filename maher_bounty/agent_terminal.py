"""Direct entry point for the existing local tool execution/review loop."""
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from .agent_feedback import run_agent_tool_feedback
from .agent_tool_router import build_local_tool_requests, SUPPORTED_AGENT_TOOLS
from .artifact_io import write_json_atomic
from .model_adapter import LocalModelAdapter
from .scope_policy import filter_in_scope_urls
from .agent_findings_report import write_agent_findings_report, summarize_execution_outcome
from .agent_evidence_review import review_agent_evidence
from .json_numbers import finite_json_float


class AgentExecutionInputError(ValueError):
    pass


def load_execution_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AgentExecutionInputError("duplicate execution input field")
            result[key] = value
        return result

    def constant(value):
        raise AgentExecutionInputError("non-finite execution input value")

    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise AgentExecutionInputError("execution input exceeds 1 MiB")
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite_json_float)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, AgentExecutionInputError):
            raise
        raise AgentExecutionInputError("cannot read valid local execution JSON") from None


def _validate_packets(packets, known):
    if not isinstance(packets, list) or len(packets) > 120:
        raise AgentExecutionInputError("requests must contain at most 120 worker packets")
    for packet in packets:
        if not isinstance(packet, dict) or set(packet) != {"agent", "tool_requests"}:
            raise AgentExecutionInputError("worker packet requires agent and tool_requests")
        if not isinstance(packet["agent"], str) or not packet["agent"].strip() or len(packet["agent"]) > 128:
            raise AgentExecutionInputError("invalid worker name")
        requests = packet["tool_requests"]
        if not isinstance(requests, list) or len(requests) > 20:
            raise AgentExecutionInputError("each worker accepts at most 20 requests")
        for request in requests:
            if not isinstance(request, dict) or set(request) - {"tool", "targets", "reason"}:
                raise AgentExecutionInputError("request accepts tool, targets and optional reason only")
            if (not isinstance(request.get("tool"), str) or request["tool"] not in SUPPORTED_AGENT_TOOLS
                    or request["tool"] == "browser-xss-auth"):
                raise AgentExecutionInputError("unsupported direct tool; authenticated browser checks require a workflow profile")
            targets = request.get("targets")
            if (not isinstance(targets, list) or not targets or len(targets) > 120
                    or any(not isinstance(url, str) or url not in known for url in targets)):
                raise AgentExecutionInputError("request targets must be exact supplied scoped URLs")
            if "reason" in request and (not isinstance(request["reason"], str) or len(request["reason"]) > 1000):
                raise AgentExecutionInputError("request reason must be a bounded string")


def run_agent_terminal(targets, scope, out_dir, *, authorized=False, requests=None,
                       local_model=False, plan_only=False, max_rounds=3, resume=False):
    if not authorized:
        raise AgentExecutionInputError("agent tool execution requires explicit authorization")
    if type(resume) is not bool or (resume and (local_model or plan_only)):
        raise AgentExecutionInputError("resume requires native execution without --local-model or --plan-only")
    if not isinstance(scope, dict) or not isinstance(targets, list) or not targets or len(targets) > 120:
        raise AgentExecutionInputError("scope object and 1-120 target URLs required")
    if any(not isinstance(url, str) or len(url) > 8192 for url in targets):
        raise AgentExecutionInputError("targets must be bounded URL strings")
    try:
        for url in targets:
            parsed = urlparse(url)
            if (url != url.strip() or parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None or parsed.fragment):
                raise AgentExecutionInputError("targets require complete HTTP URLs without credentials/fragments")
            _ = parsed.port
    except ValueError as exc:
        if isinstance(exc, AgentExecutionInputError):
            raise
        raise AgentExecutionInputError("invalid target URL") from None
    if type(max_rounds) is not int or not 1 <= max_rounds <= 3:
        raise AgentExecutionInputError("rounds must be between one and three")
    known, rejected = filter_in_scope_urls(targets, scope)
    if rejected or not known:
        raise AgentExecutionInputError("all initial targets must be explicitly in scope")
    known = list(dict.fromkeys(known))
    if requests is not None:
        _validate_packets(requests, set(known))
    root = Path(out_dir)
    checkpoint = root / "execution" / "execution-state.json"
    if resume and not checkpoint.is_file():
        raise AgentExecutionInputError("resume requires an existing execution-state.json in the original output directory")
    if not resume and not plan_only and checkpoint.exists():
        raise AgentExecutionInputError("prior execution state exists; use a fresh output directory")
    model = LocalModelAdapter() if local_model else None
    if model is not None and not model.enabled:
        # An explicit model request must not silently turn into fixed planning.
        raise AgentExecutionInputError("local GGUF model unavailable; configure MAHER_GGUF_MODEL and local-inference")
    roles = [
        {"id": "web_surface_reviewer", "mission": "Plan complementary scoped local tool checks from observed web evidence."},
        {"id": "evidence_reviewer", "mission": "Review actual execution failures and findings; distinguish candidates from proof."},
    ]
    reviews = []

    def analyze(packet):
        outputs = []
        for role in roles:
            output = model.analyze(role, {
                "scope": scope, "rules": {"active_testing": {"enabled": True}},
                "inventory": {"endpoints": [{"value": url} for url in packet["known_urls"]]},
                "execution_feedback": packet,
                "validated_evidence": review_agent_evidence(packet["findings"], packet["runs"], packet["known_urls"], scope),
                "prior_agent_evidence": outputs,
                "research_method": {"can_schedule_next_round": packet["can_schedule_next_round"]},
            })
            outputs.append(output)
        reviews.append({"round": packet["round"], "agents": outputs})
        return outputs

    native = build_local_tool_requests(known, scope=scope)
    packets = list(requests) if requests is not None else list(native["agent_results"])
    if model is not None:
        packets = [*analyze({"round": 0, "known_urls": known, "runs": [], "findings": [],
                            "decisions": [], "can_schedule_next_round": True}), *packets]
    plan = {"mode": "local_gguf_plus_native" if model else "native_fixed_planner",
            "model_inference_enabled": model is not None, "initial_targets": known,
            "initial_requests": packets, "max_rounds": max_rounds,
            "execution_policy": {"supported_tools": sorted(SUPPORTED_AGENT_TOOLS - {"browser-xss-auth"}),
                                 "arbitrary_shell_commands": False, "agent_selected_executable_paths": False},
            "plan_only": plan_only, "execution_started": False}
    # Preserve the original plan on recovery, including if binding validation
    # later rejects changed inputs. No report/result files are written yet.
    if not resume:
        write_json_atomic(root / "agent-tool-plan.json", plan)
    if plan_only:
        return {"status": "planned", "plan": plan, "runs": [], "findings": []}
    try:
        execution = run_agent_tool_feedback(packets, known, root / "execution", scope=scope,
            max_rounds=max_rounds, reviewer=analyze if model else None,
            checkpoint_path=checkpoint, resume=resume,
            checkpoint_context={"mode": plan["mode"], "initial_requests": packets})
    except ValueError:
        if not resume:
            raise
        raise AgentExecutionInputError(
            "native recovery rejected; use identical inputs and rounds, inspect checkpoint/lock, "
            "and never automatically replay an interrupted running round") from None
    counts = dict(Counter(run.get("status", "unknown") for run in execution["runs"]))
    result = {"status": "finished" if execution["runs"] else "not_run",
              "execution_resumed": resume,
              "execution_outcome": summarize_execution_outcome(execution),
              "planner_mode": plan["mode"], "model_inference_enabled": model is not None,
              "execution": execution, "run_status_counts": counts, "model_reviews": reviews,
              "evidence_review": review_agent_evidence(execution["findings"], execution["runs"],
                                  [*known, *execution.get("new_in_scope_urls", [])], scope),
              "limitations": ["process exit success does not prove vulnerability absence or exploit validity",
                              "native planning is fixed rules; model roles share one supplied local GGUF instance",
                              "only supported tool adapters execute; no arbitrary shell command generation"]}
    # Save actual execution before report rendering, preserving results if a
    # report artifact exceeds its size budget or publication fails.
    write_json_atomic(root / "agent-tool-results.json", result)
    try:
        result["finding_report"] = write_agent_findings_report(result, scope, known, root)
    except (OSError, ValueError) as exc:
        raise AgentExecutionInputError("finding report publication failed; inspect preserved agent-tool-results.json") from exc
    write_json_atomic(root / "agent-tool-results.json", result)
    return result
