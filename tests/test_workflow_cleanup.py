import json
import tempfile
import unittest
from unittest.mock import Mock
from urllib.error import URLError

from maher_bounty.workflow_execution import execute_workflows


def manifest():
    return {"identities": {"owner": {"origin": "https://example.test"}}, "workflows": [
        {"id": "lifecycle", "identity": "owner", "steps": [
            {"request": {"url": "https://example.test/create", "method": "POST"}, "expect": {"statuses": [201]}, "capture": {"id": "/id"}},
            {"request": {"url": "https://example.test/object/{{id}}"}, "expect": {"statuses": [200]}}],
         "cleanup_steps": [{"request": {"url": "https://example.test/object/{{id}}", "method": "DELETE"}, "expect": {"statuses": [204]}}]}]}


class WorkflowCleanupTests(unittest.TestCase):
    def run_case(self, responses, config=None):
        sender = Mock(spec=[], side_effect=responses)
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config or manifest(), {"assets": ["example.test"]}, td, authorized=True, transport=sender)
        self.assertNotIn("fixture-secret", json.dumps(result))
        return result, sender

    def test_cleanup_uses_captured_resource_after_success(self):
        result, sender = self.run_case([{"status": 201, "body": '{"id":42}'}, {"status": 200, "body": '{}'}, {"status": 204, "body": ''}])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["cleanup_decisions"][0]["status"], "completed")
        self.assertEqual(sender.call_args_list[-1].args[1]["url"], "https://example.test/object/42")
        self.assertEqual(sender.call_args_list[-1].args[1]["method"], "DELETE")
        self.assertEqual(len(result["observations"][0]["cleanup_observations"]), 1)

    def test_cleanup_runs_after_invariant_failure_without_erasing_finding(self):
        result, sender = self.run_case([{"status": 201, "body": '{"id":42}'}, {"status": 403, "body": '{}'}, {"status": 204, "body": ''}])
        self.assertEqual(result["decisions"][0]["status"], "invariant_failed")
        self.assertEqual(result["cleanup_decisions"][0]["status"], "completed")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(sender.call_count, 3)

    def test_cleanup_runs_after_transport_error_with_available_capture(self):
        result, sender = self.run_case([{"status": 201, "body": '{"id":42}'}, URLError("fixture-secret"), {"status": 204, "body": ''}])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["cleanup_decisions"][0]["status"], "completed")
        self.assertEqual(sender.call_count, 3)

    def test_cleanup_failure_marks_run_partial_and_is_not_a_vulnerability(self):
        result, _ = self.run_case([{"status": 201, "body": '{"id":42}'}, {"status": 200, "body": '{}'}, {"status": 500, "body": '{}'}])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["decisions"][0]["status"], "completed")
        self.assertEqual(result["cleanup_decisions"][0]["status"], "invariant_failed")
        self.assertFalse(result["findings"])

    def test_missing_capture_or_exhausted_budget_does_not_force_cleanup_traffic(self):
        for config, response in [(manifest(), {"status": 201, "body": '{}'}),
                                 ({**manifest(), "limits": {"max_requests": 1}}, {"status": 201, "body": '{"id":42}'})]:
            result, sender = self.run_case([response], config)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["cleanup_decisions"][0]["status"], "inconclusive")
            self.assertEqual(sender.call_count, 1)

    def test_invalid_cleanup_blocks_all_primary_mutations(self):
        bad = [None, {}, [None], [{"request": {"url": "https://outside.test/"}, "expect": {"statuses": [204]}}],
               [{"identity": "invented", "request": {"url": "https://example.test/"}, "expect": {"statuses": [204]}}],
               [{"request": {"url": "https://example.test/{{missing}}"}, "expect": {"statuses": [204]}}]]
        for cleanup in bad:
            config = manifest()
            config["workflows"][0]["cleanup_steps"] = cleanup
            sender = Mock(spec=[])
            with self.subTest(cleanup=cleanup), tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
                execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True, transport=sender)
            sender.assert_not_called()
