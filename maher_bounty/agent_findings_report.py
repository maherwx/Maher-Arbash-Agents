"""Complete recorded finding ledger; tool claims and model hypotheses stay distinct."""
import hashlib
import html
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path

from .artifact_io import write_json_atomic


def _entry(value, index, origin, *, hypothesis=False):
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    finding = value if isinstance(value, dict) else {}
    return {"record_id": f"{origin}-{index}",
            "record_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            "origin": origin,
            "verification": ("model_hypothesis_unverified" if hypothesis else
                             "tool_reported_validated" if finding.get("validated") is True else
                             "candidate_needs_review"),
            "severity": finding.get("severity", "unspecified"),
            "missing_details": [key for key in ("target", "evidence", "impact", "reproduction_steps", "remediation")
                                if not finding.get(key)],
            "original_record": value}


def _markdown_text(value):
    text = str(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_[\]{}()#+.!|>-])", r"\\\1", html.escape(text, quote=False))


def _json_block(value):
    content = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    longest = max((len(match.group()) for match in re.finditer(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}json\n{content}\n{fence}"


def _write_markdown(path, text):
    data = text.encode("utf-8")
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("finding Markdown report exceeds 16 MiB; records were not silently truncated")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def write_agent_findings_report(result, scope, targets, out_dir):
    execution = result["execution"]
    findings = [_entry(value, index, "tool") for index, value in enumerate(execution.get("findings", []), 1)]
    hypotheses = []
    for review in result.get("model_reviews", []):
        for agent in review.get("agents", []):
            for value in agent.get("candidate_findings", []):
                entry = _entry(value, len(hypotheses) + 1, "model", hypothesis=True)
                entry.update({"review_round": review.get("round"), "agent": agent.get("agent")})
                hypotheses.append(entry)
    hashes = Counter(item["record_sha256"] for item in findings)
    for entry in findings:
        entry["identical_tool_record_count"] = hashes[entry["record_sha256"]]
    runs = execution.get("runs", [])
    report = {"schema_version": 1, "status": "recorded_results_only",
              "scope": scope, "initial_targets": targets,
              "planner_mode": result["planner_mode"], "model_inference_enabled": result["model_inference_enabled"],
              "summary": {"tool_finding_records": len(findings), "model_hypothesis_records": len(hypotheses),
                          "unique_exact_tool_records": len(hashes),
                          "verification_counts": dict(Counter(item["verification"] for item in findings)),
                          "run_status_counts": result["run_status_counts"],
                          "remaining_deferred_request_count": execution.get("remaining_deferred_request_count", 0),
                          "stop_reason": execution.get("stop_reason")},
              "findings": findings, "model_hypotheses": hypotheses,
              "runs": runs, "decisions": execution.get("decisions", []), "rounds": execution.get("rounds", []),
              "limitations": ["all recorded findings preserved, including duplicates and missing metadata",
                              "tool-reported validation is not independent confirmation of exploitability or impact",
                              "model hypotheses never promoted into tool-confirmed findings",
                              "missing reproduction/impact/remediation details are marked, not invented",
                              "no claim of all vulnerabilities discovered; failed/deferred checks reduce coverage",
                              "findings extraction is adapter-specific; raw tool artifacts may require further review"]}
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=False, allow_nan=False)
    generation = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    report["report_generation_sha256"] = generation
    lines = ["# Local agent findings report", "", f"Report generation: `{generation}`", "",
             "All recorded results are listed. This report does not certify exhaustive vulnerability discovery.", "",
             "## Summary", "", _json_block(report["summary"]), "", "## Tool findings", ""]
    if not findings:
        lines.append("No tool finding was recorded; inspect failed and deferred checks before drawing conclusions.")
    for entry in findings:
        original = entry["original_record"]
        title = original.get("title", "Untitled finding") if isinstance(original, dict) else "Invalid finding record"
        lines.extend(["", f"### {entry['record_id']}: {_markdown_text(title)}", "", _json_block(entry)])
    lines.extend(["", "## Model hypotheses (unverified)", ""])
    for entry in hypotheses:
        lines.extend(["", f"### {entry['record_id']}", "", _json_block(entry)])
    if not hypotheses:
        lines.append("No model hypothesis was recorded.")
    lines.extend(["", "## Execution and coverage", "", _json_block({
        "initial_targets": targets, "scope": scope, "runs": runs, "decisions": report["decisions"],
        "rounds": report["rounds"]}), "", "## Limitations", "", _json_block(report["limitations"])])
    root = Path(out_dir)
    _write_markdown(root / "findings-report.md", "\n".join(lines) + "\n")
    # Authoritative JSON written last; readers must compare generation hashes
    # before combining artifacts left by an interrupted/concurrent publication.
    write_json_atomic(root / "findings-report.json", report)
    return {"json": str(root / "findings-report.json"), "markdown": str(root / "findings-report.md"),
            "report_generation_sha256": generation, "summary": report["summary"]}
