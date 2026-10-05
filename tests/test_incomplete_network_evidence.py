import tempfile
import unittest

from maher_bounty.workflow_execution import execute_workflows


class IncompleteNetworkEvidenceTests(unittest.TestCase):
    def execute(self, config, sender):
        with tempfile.TemporaryDirectory() as td:
            return execute_workflows(config, {"assets": ["app.example.test"]}, td, authorized=True, transport=sender)

    def test_incomplete_denied_observation_is_inconclusive_not_confirmed(self):
        origin = "https://app.example.test"
        config = {"identities": {n: {"origin": origin} for n in ["owner", "other"]}, "access_cases": [
            {"id": "private", "allowed": ["owner"], "denied": ["other"], "request": {"url": origin}, "proof": {"contains": ["private"]}}]}
        result = self.execute(config, lambda name, request: {"status": 200, "body": "private", "network_incomplete": name == "other"})
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])

    def test_incomplete_workflow_stops_before_capture_or_later_request(self):
        origin = "https://app.example.test"
        config = {"identities": {"owner": {"origin": origin}}, "workflows": [{"id": "state", "identity": "owner", "steps": [
            {"request": {"url": origin}, "expect": {"contains": ["private"]}, "capture": {"id": "/id"}},
            {"request": {"url": origin + "/next"}, "expect": {"statuses": [200]}}]}]}
        result = self.execute(config, lambda *_: {"status": 200, "body": "private", "network_incomplete": True})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["requests"], 1)
        self.assertFalse(result["findings"])

    def test_malformed_network_wait_option_is_rejected_before_traffic(self):
        origin = "https://app.example.test"
        config = {"engine": "browser", "identities": {"owner": {"origin": origin}},
                  "workflows": [{"id": "wait", "identity": "owner", "steps": [
                      {"request": {"url": origin, "browser": {"wait_for_network_idle": "false"}},
                       "expect": {"statuses": [200]}}]}]}
        with self.assertRaises(ValueError):
            self.execute(config, lambda *_: self.fail("must not send requests"))
