import json
import os
import unittest
from unittest.mock import patch

from maher_bounty.model_adapter import LocalModelAdapter, build_agent_context


class _Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.body).encode("utf-8")


class ModelAdapterEvidenceTests(unittest.TestCase):
    def test_context_contains_active_results_and_prior_agent_evidence(self):
        context = build_agent_context(
            {"id": "idor_reviewer", "mission": "Review access control"},
            {
                "scope": {"assets": ["https://example.test"]},
                "inventory": {"endpoints": [{"value": "https://example.test/api/item?id=1"}]},
                "active_testing": {
                    "runs": [{"tool": "nuclei", "status": "ok"}],
                    "findings": [{"title": "candidate", "evidence": "matched response"}],
                },
                "validated_evidence": {"counts": {"needs_review": 1}},
                "agent_workstreams": [{"agent": "idor_reviewer", "urls": ["https://example.test/api/item?id=1"]}],
                "prior_agent_evidence": [{"agent": "api_mapper", "observations": ["API route observed"]}],
            },
        )
        self.assertIn("active_testing", context)
        self.assertIn("validated_evidence", context)
        self.assertIn("agent_workstreams", context)
        self.assertIn("prior_agent_evidence", context)
        self.assertEqual(context["active_testing"]["findings"][0]["evidence"], "matched response")

    def test_model_request_receives_full_evidence_packet(self):
        response = _Response({"choices": [{"message": {"content": json.dumps({
            "status": "completed", "observations": ["reviewed evidence"],
            "candidate_findings": [], "evidence_notes": [], "next_checks": [],
        })}}]})
        context = {
            "inventory": {"counts": {"endpoints": 1}},
            "active_testing": {"runs": [{"tool": "nuclei", "status": "ok"}]},
            "validated_evidence": {"counts": {"needs_review": 1}},
            "prior_agent_evidence": [{"agent": "api_mapper", "observations": ["route found"]}],
        }
        with patch.dict(os.environ, {
            "MAHER_MODEL_URL": "http://127.0.0.1:8000/v1/chat/completions",
            "MAHER_MODEL_ID": "local-test",
        }), patch("maher_bounty.model_adapter.urllib.request.urlopen", return_value=response) as call:
            adapter = LocalModelAdapter()
            result = adapter.analyze({"id": "idor_reviewer", "mission": "Review access"}, context)
        self.assertEqual(adapter.mode, "local_model")
        self.assertEqual(result["status"], "completed")
        request = call.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        user_context = json.loads(payload["messages"][1]["content"])
        self.assertIn("active_testing", user_context)
        self.assertIn("validated_evidence", user_context)
        self.assertIn("prior_agent_evidence", user_context)

    def test_missing_model_is_reported_as_local_deterministic(self):
        with patch.dict(os.environ, {"MAHER_MODEL_URL": "", "MAHER_MODEL_ID": ""}):
            adapter = LocalModelAdapter()
            result = adapter.analyze({"id": "reviewer", "mission": "Review"}, {"inventory": {}})
        self.assertEqual(adapter.mode, "local_deterministic")
        self.assertEqual(result["status"], "planned")
        self.assertTrue(any("not executed" in note for note in result["evidence_notes"]))

    def test_non_loopback_model_endpoint_is_never_used(self):
        with patch.dict(os.environ, {
            "MAHER_MODEL_URL": "https://api.example.invalid/v1/chat/completions",
            "MAHER_MODEL_ID": "remote-model",
        }), patch("maher_bounty.model_adapter.urllib.request.urlopen") as open_url:
            adapter = LocalModelAdapter()
            result = adapter.analyze({"id": "reviewer", "mission": "Review"}, {"inventory": {}})
        self.assertFalse(adapter.enabled)
        self.assertEqual(adapter.mode, "local_deterministic")
        open_url.assert_not_called()
        self.assertTrue(any("external or cloud" in note for note in result["evidence_notes"]))


if __name__ == "__main__":
    unittest.main()
