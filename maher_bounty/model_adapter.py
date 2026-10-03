import json
import os
import urllib.error
import urllib.request


class LocalModelAdapter:
    """Optional adapter for any local OpenAI-compatible model server.

    The project is standalone and has no dependency on Maher OS or any cloud API.
    Set MAHER_MODEL_URL and MAHER_MODEL_ID when you want agent reasoning through
    a local model server. Without them, the project still runs and produces a
    planning report.
    """

    def __init__(self):
        self.url = os.getenv("MAHER_MODEL_URL", "").strip()
        self.model = os.getenv("MAHER_MODEL_ID", "").strip()
        self.timeout = int(os.getenv("MAHER_MODEL_TIMEOUT", "120"))

    def analyze(self, agent, context):
        if not self.url or not self.model:
            return {
                "agent": agent["id"],
                "status": "planned",
                "observations": [],
                "candidate_findings": [],
                "evidence_notes": ["No local model configured; set MAHER_MODEL_URL and MAHER_MODEL_ID to enable model-assisted analysis."],
                "next_checks": [agent.get("mission", "")],
            }

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a vulnerability-research agent operating only within the supplied authorized bug-bounty scope and rules. Return JSON only with keys: status, observations, candidate_findings, evidence_notes, next_checks.",
                },
                {
                    "role": "user",
                    "content": json.dumps({"agent": agent, "scope": context.get("scope", {}), "rules": context.get("rules", {})}, ensure_ascii=False),
                },
            ],
            "temperature": 0.2,
            "stream": False,
        }
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
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
            return result
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return {
                "agent": agent["id"],
                "status": "model_error",
                "observations": [],
                "candidate_findings": [],
                "evidence_notes": [str(exc)],
                "next_checks": [agent.get("mission", "")],
            }
