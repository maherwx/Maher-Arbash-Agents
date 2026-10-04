import unittest

from maher_bounty.workflow_intelligence import build_workflow_model, compare_identity_workflows


class WorkflowIntelligenceTests(unittest.TestCase):
    def test_builds_state_machine_and_identity_divergence(self):
        records = [
            {"sequence": 1, "session": "a", "identity": "alice", "tenant": "t1", "method": "GET", "url": "https://app.test/items", "status": 200},
            {"sequence": 2, "session": "a", "identity": "alice", "tenant": "t1", "method": "POST", "url": "https://app.test/items/1/action", "status": 200},
            {"sequence": 1, "session": "b", "identity": "bob", "tenant": "t2", "method": "GET", "url": "https://app.test/items", "status": 200},
            {"sequence": 2, "session": "b", "identity": "bob", "tenant": "t2", "method": "POST", "url": "https://app.test/items/1/action", "status": 403},
        ]
        model = build_workflow_model(records)
        self.assertEqual(model["session_count"], 2)
        self.assertGreaterEqual(model["state_count"], 2)
        self.assertEqual(model["transition_count"], 2)
        diff = compare_identity_workflows(model)
        self.assertEqual(diff["divergence_count"], 1)
        self.assertEqual(diff["divergences"][0]["priority"], "high")


if __name__ == "__main__":
    unittest.main()
