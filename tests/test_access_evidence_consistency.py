import json
import tempfile
import unittest

from maher_bounty.workflow_execution import execute_workflows


class AccessEvidenceConsistencyTests(unittest.TestCase):
    def execute(self, sequences):
        calls = {}
        config = {"identities": {name: {"origin": "https://example.test"} for name in ["owner", "other", "anonymous"]},
                  "access_cases": [{"id": "private", "allowed": ["owner"], "denied": ["other", "anonymous"],
                                    "request": {"url": "https://example.test/private"}, "proof": {"json_equals": {"/id": 42}}}]}
        def sender(name, request):
            index = calls.get(name, 0)
            calls[name] = index + 1
            passed = sequences.get(name, [True, True])[index]
            return {"status": 200, "body": '{"id":42,"secret":"fixture-secret"}' if passed else '{"id":43}'}
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True, transport=sender)
        self.assertNotIn("fixture-secret", json.dumps(result))
        return result, calls

    def test_both_orders_of_fluctuating_resource_proof_are_inconclusive(self):
        for outcomes in [[True, False], [False, True]]:
            with self.subTest(outcomes=outcomes):
                result, calls = self.execute({"other": outcomes})
                self.assertEqual(result["status"], "partial")
                self.assertFalse(result["findings"])
                self.assertNotIn("anonymous", calls)
                self.assertEqual(result["decisions"][0]["status"], "inconclusive")
                rows = result["observations"][0]["observations"][-2:]
                self.assertEqual([row["resource_proof_passed"] for row in rows], outcomes)

    def test_repeatable_resource_absence_completes_without_finding(self):
        result, calls = self.execute({"other": [False, False], "anonymous": [False, False]})
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["findings"])
        self.assertEqual(calls, {"owner": 2, "other": 2, "anonymous": 2})

    def test_later_instability_preserves_earlier_repeatable_finding(self):
        result, calls = self.execute({"other": [True, True], "anonymous": [True, False]})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["validated"])
        self.assertEqual(result["findings"][0]["evidence"]["identity"], "other")
