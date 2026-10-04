import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request


def _is_local_endpoint(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in {"localhost", "host.docker.internal"}:
            return True
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def _configured_endpoints() -> list[dict]:
    pool = os.getenv("MAHER_MODEL_POOL", "").strip()
    endpoints = []
    if pool:
        try:
            parsed = json.loads(pool)
            if isinstance(parsed, list):
                for row in parsed:
                    if isinstance(row, dict) and row.get("url") and row.get("model"):
                        endpoints.append({
                            "url": str(row["url"]).strip(),
                            "model": str(row["model"]).strip(),
                            "name": str(row.get("name") or row["model"]).strip(),
                        })
        except json.JSONDecodeError:
            pass
    legacy_url = os.getenv("MAHER_MODEL_URL", "").strip()
    legacy_model = os.getenv("MAHER_MODEL_ID", "").strip()
    if legacy_url and legacy_model:
        endpoints.append({"url": legacy_url, "model": legacy_model, "name": legacy_model})

    seen = set()
    unique = []
    for row in endpoints:
        key = (row["url"], row["model"])
        if key in seen:
            continue
        seen.add(key)
        if _is_local_endpoint(row["url"]):
            unique.append(row)
    return unique


class LocalModelAdapter:
    """Failover adapter for local/self-hosted OpenAI-compatible model servers.

    Configure one server with MAHER_MODEL_URL + MAHER_MODEL_ID, or a fallback pool
    with MAHER_MODEL_POOL as JSON:
    [{"name":"primary","url":"http://127.0.0.1:11434/v1/chat/completions","model":"model-a"}, ...]

    Non-local/public endpoints are ignored by design.
    """

    def __init__(self):
        self.endpoints = _configured_endpoints()
        self.timeout = int(os.getenv("MAHER_MODEL_TIMEOUT", "120"))
        self.last_endpoint = None

    def status(self) -> dict:
        return {
            "configured": bool(self.endpoints),
            "endpoint_count": len(self.endpoints),
            "endpoints": [{"name": x["name"], "model": x["model"], "url": x["url"]} for x in self.endpoints],
            "local_only": True,
            "last_endpoint": self.last_endpoint,
        }

    @staticmethod
    def _clean_json(text: str) -> dict:
        text = text.strip()
        if text.startswith("~~~json"):
            text = text[7:]
        elif text.startswith("~~~"):
            text = text[3:]
        if text.endswith("~~~"):
            text = text[:-3]
        result = json.loads(text.strip())
        if not isinstance(result, dict):
            raise ValueError("model response is not a JSON object")
        return result

    def _request(self, endpoint: dict, agent: dict, context: dict) -> dict:
        inventory = context.get("inventory", {})
        payload = {
            "model": endpoint["model"],
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a local vulnerability-research analyst operating only within the supplied "
                        "authorized scope and rules. Correlate evidence conservatively. Do not treat scanner "
                        "output as proof. Return JSON only with keys: status, observations, candidate_findings, "
                        "evidence_notes, next_checks."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps({
                        "agent": agent,
                        "scope": context.get("scope", {}),
                        "rules": context.get("rules", {}),
                        "inventory": inventory,
                        "application_intelligence": context.get("application_intelligence", {}),
                        "validated_evidence": context.get("validated_evidence", {}),
                        "prior_agent_evidence": context.get("prior_agent_evidence", []),
                        "research_method": context.get("research_method", {}),
                    }, ensure_ascii=False),
                },
            ],
            "temperature": 0.15,
            "stream": False,
        }
        req = urllib.request.Request(
            endpoint["url"],
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        result = self._clean_json(raw["choices"][0]["message"]["content"])
        result["agent"] = agent["id"]
        result.setdefault("status", "completed")
        result.setdefault("observations", [])
        result.setdefault("candidate_findings", [])
        result.setdefault("evidence_notes", [])
        result.setdefault("next_checks", [])
        result["model_backend"] = endpoint["name"]
        self.last_endpoint = endpoint["name"]
        return result

    def analyze(self, agent, context):
        inventory = context.get("inventory", {})
        if not self.endpoints:
            counts = inventory.get("counts", {}) if isinstance(inventory, dict) else {}
            return {
                "agent": agent["id"],
                "status": "planned",
                "observations": [
                    f"Inventory available: {counts.get('hosts', 0)} hosts, "
                    f"{counts.get('endpoints', 0)} endpoints, {counts.get('http', 0)} HTTP records"
                ],
                "candidate_findings": [],
                "evidence_notes": [
                    "No local model configured; set MAHER_MODEL_POOL or MAHER_MODEL_URL/MAHER_MODEL_ID."
                ],
                "next_checks": [agent.get("mission", "")],
                "model_backend": None,
            }

        errors = []
        for endpoint in self.endpoints:
            try:
                return self._request(endpoint, agent, context)
            except (urllib.error.URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{endpoint['name']}: {type(exc).__name__}: {exc}")

        return {
            "agent": agent["id"],
            "status": "model_error",
            "observations": [],
            "candidate_findings": [],
            "evidence_notes": errors[-5:],
            "next_checks": [agent.get("mission", "")],
            "model_backend": None,
        }
