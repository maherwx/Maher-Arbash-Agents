"""Direct entry point for the existing local tool execution/review loop."""
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from .agent_feedback import run_agent_tool_feedback
from .agent_tool_router import (build_local_tool_requests, SUPPORTED_AGENT_TOOLS,
                                DIRECT_AGENT_TOOLS, AGENT_TOOL_PROFILES, _origin)
from .artifact_io import write_json_atomic
from .model_adapter import LocalModelAdapter
from .scope_policy import filter_in_scope_urls
from .agent_findings_report import write_agent_findings_report, summarize_execution_outcome
from .agent_evidence_review import review_agent_evidence
from .json_numbers import finite_json_float
from .tool_readiness import tool_readiness_snapshot, agent_tool_availability_context
from .workflow_execution import validate_manifest
from .browser_xss import load_browser_xss_profile
from .traffic_ingest import ingest_traffic


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


def _validate_packets(packets, known, browser_xss_profile=None, allowed_tools=None):
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
            if not isinstance(request.get("tool"), str) or request["tool"] not in SUPPORTED_AGENT_TOOLS:
                raise AgentExecutionInputError("unsupported direct tool")
            if request["tool"] == "browser-xss-auth" and browser_xss_profile is None:
                raise AgentExecutionInputError("authenticated browser checks require a supplied workflow profile")
            if allowed_tools is not None and request["tool"] not in allowed_tools:
                if request["tool"] == "browser-xss-auth" and browser_xss_profile is not None:
                    raise AgentExecutionInputError("authenticated browser prerequisites or selected profile are unavailable")
                raise AgentExecutionInputError("requested tool is outside the selected tool profile")
            targets = request.get("targets")
            if (not isinstance(targets, list) or not targets or len(targets) > 120
                    or any(not isinstance(url, str) or url not in known for url in targets)):
                raise AgentExecutionInputError("request targets must be exact supplied scoped URLs")
            if request["tool"] == "browser-xss-auth" and any(
                    not urlparse(url).query
                    or _origin(url) != _origin(browser_xss_profile["identity"]["origin"])
                    for url in targets):
                raise AgentExecutionInputError("authenticated browser targets must be query URLs at the supplied identity origin")
            if "reason" in request and (not isinstance(request["reason"], str) or len(request["reason"]) > 1000):
                raise AgentExecutionInputError("request reason must be a bounded string")


def run_agent_terminal(targets, scope, out_dir, *, authorized=False, requests=None,
                       local_model=False, plan_only=False, max_rounds=3, resume=False,
                       tool_profile="all", workflow_manifest=None, traffic_path=None,
                       operator_brief=None, selected_tools=None):
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
    if tool_profile not in AGENT_TOOL_PROFILES:
        raise AgentExecutionInputError("unknown local tool profile")
    if operator_brief is not None and (not isinstance(operator_brief, str) or len(operator_brief) > 4000):
        raise AgentExecutionInputError("operator brief must be a string no longer than 4000 characters")
    operator_brief = operator_brief.strip() if isinstance(operator_brief, str) else ""
    if operator_brief and not local_model:
        raise AgentExecutionInputError("operator brief requires --local-model; external model APIs are not used")
    known, rejected = filter_in_scope_urls(targets, scope)
    if rejected or not known:
        raise AgentExecutionInputError("all initial targets must be explicitly in scope")
    known = list(dict.fromkeys(known))
    traffic_summary = {"provided": bool(traffic_path), "imported_records": 0,
                       "in_scope_urls_added": 0, "out_of_scope_urls_dropped": 0,
                       "invalid_urls_dropped": 0, "url_limit_dropped": 0}
    if traffic_path:
        records = ingest_traffic(traffic_path, kind="auto")
        observed = []
        invalid_record_count = 0
        for row in records:
            if isinstance(row, dict) and isinstance(row.get("url"), str):
                observed.append(row["url"])
            else:
                invalid_record_count += 1
        valid_observed = []
        for value in observed:
            if len(value) > 8192 or value != value.strip():
                continue
            try:
                parsed = urlparse(value)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                        or parsed.username is not None or parsed.password is not None or parsed.fragment):
                    continue
                _ = parsed.port
            except ValueError:
                continue
            valid_observed.append(value)
        traffic_summary["invalid_urls_dropped"] = invalid_record_count + len(observed) - len(valid_observed)
        traffic_urls, outside_traffic = filter_in_scope_urls(valid_observed, scope)
        traffic_summary["imported_records"] = len(records)
        traffic_summary["out_of_scope_urls_dropped"] = len(outside_traffic)
        combined = list(dict.fromkeys([*known, *traffic_urls]))
        traffic_summary["in_scope_urls_added"] = max(0, len(combined) - len(known))
        traffic_summary["url_limit_dropped"] = max(0, len(combined) - 120)
        known = combined[:120]
    browser_xss_profile = None
    if workflow_manifest is not None:
        try:
            validate_manifest(workflow_manifest, scope)
            browser_xss_profile = load_browser_xss_profile(workflow_manifest, scope)
        except Exception:
            raise AgentExecutionInputError("invalid local authenticated workflow profile") from None
        if browser_xss_profile is None:
            raise AgentExecutionInputError("workflow manifest must contain browser_xss_profile")
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
    allowed_tools = set(AGENT_TOOL_PROFILES[tool_profile])
    if selected_tools is not None:
        if (not isinstance(selected_tools, (list, tuple, set))
                or any(not isinstance(name, str) or name not in SUPPORTED_AGENT_TOOLS for name in selected_tools)):
            raise AgentExecutionInputError("selected tools must use supported adapter names")
        selected_set = set(selected_tools)
        if "browser-xss-auth" in selected_set and browser_xss_profile is None:
            raise AgentExecutionInputError("browser-xss-auth requires --workflow-manifest with a supplied identity profile")
        profile_tools = set(allowed_tools)
        if browser_xss_profile is not None and tool_profile in {"all", "web"}:
            profile_tools.add("browser-xss-auth")
        if selected_set - profile_tools:
            raise AgentExecutionInputError("selected adapters are outside the chosen tool profile")
        allowed_tools.intersection_update(selected_set)
    readiness = tool_readiness_snapshot()
    available_tools = {row["tool"] for row in readiness["tools"] if row.get("available") is True}
    if (browser_xss_profile is not None and tool_profile in {"all", "web"}
            and (selected_tools is None or "browser-xss-auth" in selected_tools)):
        allowed_tools.add("browser-xss-auth")
        if "browser-xss" in available_tools:
            available_tools.add("browser-xss-auth")
    if selected_tools is not None and "browser-xss-auth" in selected_tools:
        if browser_xss_profile is None:
            raise AgentExecutionInputError("browser-xss-auth requires --workflow-manifest with a supplied identity profile")
        if tool_profile not in {"all", "web"}:
            raise AgentExecutionInputError("authenticated browser checks require the web or all tool profile")
        if "browser-xss" not in available_tools:
            raise AgentExecutionInputError("authenticated browser prerequisite is missing: install the local Playwright package")
    if requests is not None:
        _validate_packets(requests, set(known), browser_xss_profile, allowed_tools)
    availability_context = agent_tool_availability_context(
        readiness, allowed_tools, tool_profile, browser_xss_profile=browser_xss_profile is not None)
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
                "tool_availability": availability_context,
                "operator_brief": operator_brief,
            })
            outputs.append(output)
        reviews.append({"round": packet["round"], "agents": outputs})
        return outputs

    native = build_local_tool_requests(known, scope=scope, enabled_tools=allowed_tools,
                                       available_tools=available_tools,
                                       browser_xss_profile=browser_xss_profile)
    packets = list(requests) if requests is not None else list(native["agent_results"])
    if model is not None:
        packets = [*analyze({"round": 0, "known_urls": known, "runs": [], "findings": [],
                            "decisions": [], "can_schedule_next_round": True}), *packets]
    plan = {"mode": "local_gguf_plus_native" if model else "native_fixed_planner",
            "model_inference_enabled": model is not None, "initial_targets": known,
            "initial_requests": packets, "max_rounds": max_rounds,
            "execution_policy": {"supported_tools": sorted(DIRECT_AGENT_TOOLS |
                                                       ({"browser-xss-auth"} if "browser-xss-auth" in allowed_tools else set())),
                                 "selected_profile": tool_profile,
                                 "selected_tools": sorted(allowed_tools),
                                 "arbitrary_shell_commands": False, "agent_selected_executable_paths": False,
                                 "authenticated_profile_sha256": (browser_xss_profile.get("profile_sha256")
                                     if browser_xss_profile else None)},
            "tool_readiness": readiness,
            "traffic_import": traffic_summary,
            "operator_brief_used": bool(operator_brief),
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
            checkpoint_context={"mode": plan["mode"], "initial_requests": packets,
                                "tool_profile": tool_profile, "selected_tools": sorted(allowed_tools),
                                "authenticated_profile_sha256": (browser_xss_profile.get("profile_sha256")
                                    if browser_xss_profile else None)},
            allowed_tools=allowed_tools, available_tools=available_tools,
            browser_xss_profile=browser_xss_profile)
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
              "tool_profile": tool_profile, "tool_readiness": plan["tool_readiness"],
              "traffic_import": traffic_summary,
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
