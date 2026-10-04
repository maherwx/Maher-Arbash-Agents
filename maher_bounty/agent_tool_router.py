from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import urlparse

from .active_testing import _dalfox_findings, _exec, _nuclei_findings
from .scope_policy import filter_in_scope_urls


SUPPORTED_AGENT_TOOLS = {"nuclei", "dalfox", "zap-baseline.py"}
MAX_AGENT_REQUESTS = 8
MAX_AGENT_TARGETS = 30
MAX_ZAP_ORIGINS = 2


def _request_rows(results: list[dict]) -> list[dict]:
    rows = []
    for result in results:
        requests = result.get("tool_requests", [])
        if not isinstance(requests, list):
            continue
        for request in requests:
            if isinstance(request, dict):
                rows.append({"agent": result.get("agent"), **request})
            if len(rows) >= MAX_AGENT_REQUESTS:
                return rows
    return rows


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def run_agent_tool_requests(
    agent_results: list[dict],
    known_urls: list[str],
    out_dir: str | Path,
    *,
    scope: dict,
) -> dict:
    """Run a small allowlisted follow-up set on already-discovered in-scope URLs.

    Model output can select a known tool and known URL only; it cannot supply
    command arguments, executable paths, hosts, or arbitrary payloads.
    """
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    allowed, rejected = filter_in_scope_urls(known_urls, scope)
    known = set(allowed)
    requests = _request_rows(agent_results)
    selected = {"nuclei": [], "dalfox": [], "zap-baseline.py": []}
    decisions = []
    seen = {name: set() for name in selected}
    target_budget = MAX_AGENT_TARGETS

    for row in requests:
        tool = str(row.get("tool", "")).strip().lower()
        if tool not in SUPPORTED_AGENT_TOOLS:
            decisions.append({"agent": row.get("agent"), "tool": tool or None, "status": "rejected", "reason": "tool_not_allowlisted"})
            continue
        raw_targets = row.get("targets", [])
        if isinstance(raw_targets, str):
            raw_targets = [raw_targets]
        if not isinstance(raw_targets, list):
            raw_targets = []
        candidates = [value for value in raw_targets if isinstance(value, str)]
        in_scope, out_scope = filter_in_scope_urls(candidates, scope)
        eligible = []
        for url in in_scope:
            if url not in known:
                continue
            parsed = urlparse(url)
            if tool == "dalfox" and not parsed.query:
                continue
            if url not in seen[tool] and target_budget > 0:
                seen[tool].add(url)
                eligible.append(url)
                target_budget -= 1
        if out_scope or any(value not in known for value in candidates if value not in out_scope):
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "filtered",
                "out_of_scope_count": len(out_scope),
                "unknown_url_count": sum(1 for value in candidates if value not in known and value not in out_scope),
            })
        if eligible:
            selected[tool].extend(eligible)
            decisions.append({
                "agent": row.get("agent"), "tool": tool, "status": "queued",
                "target_count": len(eligible), "reason": str(row.get("reason", ""))[:300],
            })
        elif not out_scope:
            decisions.append({"agent": row.get("agent"), "tool": tool, "status": "skipped", "reason": "no_known_eligible_targets"})

    runs, findings = [], []
    nuclei_urls = list(dict.fromkeys(selected["nuclei"]))
    if nuclei_urls:
        if shutil.which("nuclei"):
            target_file = root / "nuclei-followup-targets.txt"
            target_file.write_text("\n".join(nuclei_urls) + "\n", encoding="utf-8")
            output = root / "nuclei-followup.jsonl"
            runs.append(_exec([
                "nuclei", "-l", str(target_file), "-jsonl",
                "-severity", "medium,high,critical",
                "-rate-limit", "3", "-concurrency", "2", "-timeout", "10",
                "-retries", "1", "-exclude-tags", "dos,intrusive",
                "-o", str(output),
            ], timeout=180))
            findings.extend(_nuclei_findings(output))
        else:
            runs.append({"tool": "nuclei", "status": "missing", "reason": "agent-requested nuclei follow-up; binary not installed"})

    dalfox_urls = list(dict.fromkeys(selected["dalfox"]))
    if dalfox_urls:
        if shutil.which("dalfox"):
            target_file = root / "dalfox-followup-targets.txt"
            target_file.write_text("\n".join(dalfox_urls) + "\n", encoding="utf-8")
            output = root / "dalfox-followup.txt"
            runs.append(_exec(["dalfox", "file", str(target_file), "--silence"], timeout=180, output=output))
            findings.extend(_dalfox_findings(output, dalfox_urls[0]))
        else:
            runs.append({"tool": "dalfox", "status": "missing", "reason": "agent-requested XSS follow-up; binary not installed"})

    zap_urls = list(dict.fromkeys(_origin(url) for url in selected["zap-baseline.py"] if _origin(url)))[:MAX_ZAP_ORIGINS]
    for index, origin in enumerate(zap_urls, start=1):
        if shutil.which("zap-baseline.py"):
            output_json = root / f"zap-agent-followup-{index}.json"
            output_html = root / f"zap-agent-followup-{index}.html"
            runs.append(_exec([
                "zap-baseline.py", "-t", origin, "-m", "2", "-T", "30",
                "-J", str(output_json), "-r", str(output_html),
            ], timeout=180))
        else:
            runs.append({"tool": "zap-baseline.py", "status": "missing", "target": origin, "reason": "agent-requested ZAP baseline; binary not installed"})
    return {
        "mode": "allowlisted_agent_followups",
        "request_count": len(requests),
        "known_in_scope_url_count": len(known),
        "rejected_inventory_url_count": len(rejected),
        "decisions": decisions,
        "runs": runs,
        "findings": findings,
    }
