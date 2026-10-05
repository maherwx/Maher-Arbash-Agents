import ipaddress
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def _is_loopback_model_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if host == "localhost":
            return True
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError):
        return False


_AGENT_CONTEXT_FIELDS = (
    "scope",
    "rules",
    "inventory",
    "architecture_topology",
    "application_graph",
    "application_intelligence",
    "agent_workstreams",
    "validated_evidence",
    "native_engine_analysis",
    "active_testing",
    "active_findings",
    "traffic_evidence",
    "hypotheses",
    "prior_agent_evidence",
    "research_directives",
    "research_method",
)


def _bounded_context(value, *, depth=0):
    """Keep model requests useful and bounded even for large scan reports."""
    if depth >= 7:
        return "[nested context omitted]"
    if isinstance(value, dict):
        return {
            str(key): _bounded_context(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_context(item, depth=depth + 1) for item in value[:120]]
    if isinstance(value, str):
        return value[:12000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:1000]


def build_agent_context(agent, context):
    """Pass the complete evidence packet, not only the asset inventory."""
    packet = {"agent": agent}
    for field in _AGENT_CONTEXT_FIELDS:
        if field in context:
            packet[field] = context[field]
    return _bounded_context(packet)


class LocalModelAdapter:
    """Optional adapter for any local OpenAI-compatible model server.

    The project is standalone and has no dependency on Maher OS or any cloud API.
    Set MAHER_MODEL_URL and MAHER_MODEL_ID to enable model-assisted analysis.
    """

    def __init__(self):
        configured_url = os.getenv("MAHER_MODEL_URL", "").strip()
        self.local_endpoint_allowed = not configured_url or _is_loopback_model_url(configured_url)
        self.url = configured_url if self.local_endpoint_allowed else ""
        self.model = os.getenv("MAHER_MODEL_ID", "").strip()
        self.timeout = max(1, min(int(os.getenv("MAHER_MODEL_TIMEOUT", "120")), 300))

    @property
    def enabled(self):
        return bool(self.url and self.model)

    @property
    def mode(self):
        return "local_model" if self.enabled else "local_deterministic"

    def analyze(self, agent, context):
        inventory = context.get("inventory", {})
        if not self.enabled:
            counts = inventory.get("counts", {}) if isinstance(inventory, dict) else {}
            return {
                "agent": agent["id"],
                "status": "planned",
                "observations": [
                    f"Inventory available: {counts.get('hosts', 0)} hosts, {counts.get('endpoints', 0)} endpoints, {counts.get('http', 0)} HTTP records"
                ],
                "candidate_findings": [],
                "evidence_notes": [
                    (
                        "Non-loopback model endpoints are disabled; no external or cloud model request was sent."
                        if not self.local_endpoint_allowed else
                        "No local inference model is configured. The deterministic on-device tool coordinator still runs authorized specialist tools."
                    )
                ],
                "next_checks": [agent.get("mission", "")],
                "tool_requests": [],
            }

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a specialist vulnerability-research agent. Work only within the "
                        "provided authorization scope and assigned mission. The user message contains "
                        "the full available evidence packet: scan runs, findings, application model, "
                        "hypotheses, prior agents' evidence, and the five passive advanced traffic analyses " 
                        "(surface map, authentication-boundary comparison, response posture, parameter behavior, "
                        "and workflow transitions). Treat these as observations from captured traffic, not proof "
                        "of an exploitable issue. Do not claim a check ran unless its "
                        "tool run is present. Never invent observations, endpoints, or proof. For each "
                        "candidate finding, cite the exact in-scope URL and supplied evidence; distinguish "
                        "observed facts from hypotheses and proposed next checks. Prefer safe, "
                        "non-destructive validation and respect all program rules. Return JSON only "
                        "with keys: status, observations, candidate_findings, evidence_notes, next_checks, tool_requests. "
                        "tool_requests must be a list of objects with tool set only to hakrawler, katana, httpx, nuclei, dalfox, zap-baseline.py, nikto, nmap, tlsx, whatweb, wafw00f, dnsx, naabu, ffuf, gobuster, subfinder, assetfinder, waybackurls, gau, or alterx "
                        "and targets containing only exact URLs already present in the supplied in-scope evidence, or target_refs containing IDs from scoped Burp traffic summaries. "
                        "The local coordinator invokes these tools through a bounded shell-backed allowlist with fixed safe argument templates and reuses prior coverage. "
                        "Never provide shell commands, executable paths, flags, new hosts, or payloads. Request a tool only when "
                        "evidence justifies a distinct follow-up; otherwise return an empty list."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(build_agent_context(agent, context), ensure_ascii=False),
                },
            ],
            "temperature": 0.2,
            "stream": False,
        }
        req = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
            text = raw["choices"][0]["message"]["content"].strip()
            if text.startswith("```json"):
                text = text[7:]
            elif text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            result = json.loads(text.strip())
            if not isinstance(result, dict):
                raise ValueError("model response is not a JSON object")
            result["agent"] = agent["id"]
            result.setdefault("status", "completed")
            result.setdefault("observations", [])
            result.setdefault("candidate_findings", [])
            result.setdefault("evidence_notes", [])
            result.setdefault("next_checks", [])
            result.setdefault("tool_requests", [])
            return result
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return {
                "agent": agent["id"],
                "status": "model_error",
                "observations": [],
                "candidate_findings": [],
                "evidence_notes": [str(exc)],
                "next_checks": [agent.get("mission", "")],
                "tool_requests": [],
            }
