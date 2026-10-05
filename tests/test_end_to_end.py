import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.differential import compare_responses
from maher_bounty.hypothesis_engine import build_hypotheses
from maher_bounty.knowledge_graph import build_application_graph
from maher_bounty.persistence import ResearchStore
from maher_bounty.result_store import build_inventory


class EndToEndReadinessTests(unittest.TestCase):
    def test_inventory_hypothesis_graph_persistence_pipeline(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "subfinder.txt").write_text("api.example.com\napp.example.com\n", encoding="utf-8")
            (root / "assetfinder.txt").write_text("api.example.com\n", encoding="utf-8")
            (root / "gau.txt").write_text(
                "https://api.example.com/v1/users?id=1\n"
                "https://api.example.com/v2/users?id=1\n"
                "https://app.example.com/auth/login\n",
                encoding="utf-8",
            )
            (root / "httpx.jsonl").write_text(
                json.dumps({"url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx"]})+"\n",
                encoding="utf-8",
            )

            inventory = build_inventory(root)
            self.assertEqual(inventory["counts"]["hosts"], 2)
            self.assertGreaterEqual(inventory["counts"]["endpoints"], 3)

            hypotheses = build_hypotheses(inventory)
            self.assertTrue(any(h["type"] == "api_version_drift" for h in hypotheses))

            graph = build_application_graph(inventory, hypotheses)
            self.assertGreater(graph["stats"]["nodes"], 0)
            self.assertGreater(graph["stats"]["edges"], 0)

            store = ResearchStore(root / "research.db")
            run_id = store.create_run({"program": "CI Test"})
            store.checkpoint(run_id, "inventory", inventory)
            store.add_evidence(run_id, "ci", "inventory", inventory)
            store.finish(run_id)
            store.db.close()

    def test_differential_engine(self):
        result = compare_responses(
            {"status": 200, "headers": {"Content-Type": "application/json"}, "body": {"role": "user"}},
            {"status": 200, "headers": {"Content-Type": "application/json"}, "body": {"role": "admin"}},
        )
        self.assertTrue(result["material_difference"])
        self.assertLess(result["body_similarity"], 1.0)


if __name__ == "__main__":
    unittest.main()
