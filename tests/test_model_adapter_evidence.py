import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.model_adapter import LocalModelAdapter, build_agent_context


class _FakeLlama:
    instances = 0
    calls = 0

    def __init__(self, **kwargs):
        type(self).instances += 1
        self.kwargs = kwargs

    def create_chat_completion(self, **kwargs):
        type(self).calls += 1
        return {"choices": [{"message": {"content": json.dumps({
            "status": "completed",
            "observations": ["reviewed evidence"],
            "candidate_findings": [],
            "evidence_notes": [],
            "next_checks": [],
            "tool_requests": [],
        })}}]}


class ModelAdapterEvidenceTests(unittest.TestCase):
    def setUp(self):
        _FakeLlama.instances = 0
        _FakeLlama.calls = 0

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

    def test_in_process_gguf_model_receives_full_evidence_and_is_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            model_path = Path(temp) / "local-model.gguf"
            model_path.write_bytes(b"test placeholder")
            fake_module = types.SimpleNamespace(Llama=_FakeLlama)
            with patch.dict(sys.modules, {"llama_cpp": fake_module}), patch.dict(os.environ, {
                "MAHER_GGUF_MODEL": str(model_path),
                "MAHER_MODEL_CONTEXT": "8192",
                "MAHER_MODEL_THREADS": "2",
            }, clear=False):
                adapter = LocalModelAdapter()
                context = {
                    "inventory": {"counts": {"endpoints": 1}},
                    "active_testing": {"runs": [{"tool": "nuclei", "status": "ok"}]},
                    "validated_evidence": {"counts": {"needs_review": 1}},
                    "prior_agent_evidence": [{"agent": "api_mapper", "observations": ["route found"]}],
                }
                first = adapter.analyze({"id": "idor_reviewer", "mission": "Review access"}, context)
                second = adapter.analyze({"id": "xss_reviewer", "mission": "Review script inputs"}, context)

        self.assertEqual(adapter.mode, "in_process_local_gguf")
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "completed")
        self.assertEqual(_FakeLlama.instances, 1)
        self.assertEqual(_FakeLlama.calls, 2)
        self.assertEqual(adapter._model.kwargs["n_ctx"], 8192)
        self.assertEqual(adapter._model.kwargs["n_threads"], 2)

    def test_missing_model_uses_local_deterministic_coordinator_without_api(self):
        with patch.dict(os.environ, {"MAHER_GGUF_MODEL": ""}, clear=False):
            adapter = LocalModelAdapter()
            result = adapter.analyze({"id": "reviewer", "mission": "Review"}, {"inventory": {}})
        self.assertEqual(adapter.mode, "local_deterministic")
        self.assertEqual(result["status"], "planned")
        self.assertTrue(any("No model API or cloud service" in note for note in result["evidence_notes"]))

    def test_remote_api_environment_setting_is_ignored(self):
        with patch.dict(os.environ, {
            "MAHER_GGUF_MODEL": "",
            "MAHER_MODEL_URL": "https://api.example.invalid/v1/chat/completions",
            "MAHER_MODEL_ID": "remote-model",
        }, clear=False):
            adapter = LocalModelAdapter()
            result = adapter.analyze({"id": "reviewer", "mission": "Review"}, {"inventory": {}})
        self.assertFalse(adapter.enabled)
        self.assertEqual(adapter.mode, "local_deterministic")
        self.assertEqual(result["status"], "planned")

    def test_malformed_local_model_response_is_reported(self):
        class BadModel:
            def create_chat_completion(self, **kwargs):
                return {"choices": [{"message": {"content": "not json"}}]}

        with tempfile.TemporaryDirectory() as temp:
            model_path = Path(temp) / "local-model.gguf"
            model_path.touch()
            with patch.dict(sys.modules, {"llama_cpp": types.SimpleNamespace(Llama=lambda **kwargs: BadModel())}), \
                 patch.dict(os.environ, {"MAHER_GGUF_MODEL": str(model_path)}, clear=False):
                result = LocalModelAdapter().analyze({"id": "reviewer", "mission": "Review"}, {"inventory": {}})
        self.assertEqual(result["status"], "model_error")
        self.assertIn("JSON object", result["evidence_notes"][0])


if __name__ == "__main__":
    unittest.main()
