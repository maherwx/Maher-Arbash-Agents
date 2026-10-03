import json
import os
import urllib.error
import urllib.request


class LocalModelAdapter:
    """Connect agents to a local/self-hosted OpenAI-compatible runtime.

    Defaults match the local Maher OS runtime. Override with environment variables:
      MAHER_MODEL_URL=http://127.0.0.1:39841/v1/chat/completions
      MAHER_MODEL_ID=maher-local
      MAHER_MODEL_TIMEOUT=120
    """

    def __init__(self):
        self.url = os.getenv(
            "MAHER_MODEL_URL",
            "http://127.0.0.1:39841/v1/chat/completions",
        )
        self.model = os.getenv("MAHER_MODEL_ID", "maher-local")
        self.timeout = int(os.getenv("MAHER_MODEL_TIMEOUT", "120"))

    def analyze(self, agent, context):
        system = (
            "You are a vulnerability-research agent working only within the supplied "
            "authorized bug-bounty scope and rules. Analyze the supplied context for your "
            "assigned mission. Do not act outside scope. Return JSON only with keys: "
            "status, observations, candidate_findings, evidence_notes, next_checks."
        )
        user = json.dumps(
            {
                "agent": agent,
                "scope": context.get("scope", {}),
                "rules": context.get("rules", {}),
            },
            ensure_ascii=False,
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
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
            if text.startswith("```"):
                text = text.strip("`")
                if text.lstrip().startswith("json"):
                    text = text.lstrip()[4:].lstrip()
            result = json.loads(text)
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
