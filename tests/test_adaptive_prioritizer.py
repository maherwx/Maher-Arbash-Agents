import unittest

from maher_bounty.adaptive_prioritizer import rank_analysis_targets


class AdaptivePrioritizerTests(unittest.TestCase):
    def test_fuses_independent_signals_and_ranks_stronger_target_first(self):
        result = rank_analysis_targets(
            anomalies={"anomalies": [{"route_shape": "/account", "anomaly_score": 80, "observations": 8}]},
            workflow_divergences={"divergences": [{"target": "/account", "contexts": [{"identity": "a"}, {"identity": "b"}]}]},
            protocols={"signals": [{"protocol": "graphql", "key": "/account", "confidence": 0.95, "metadata": {}}]},
            source_correlations={"correlations": [{"route": "/account", "file": "account.py", "sinks": {"sql": 1}, "runtime_observations": [{"status": 200}]}]},
            database={"raw_query_sites": [{"file": "other.py", "line": 10}]},
        )
        self.assertGreaterEqual(result["target_count"], 2)
        self.assertEqual(result["targets"][0]["key"], "/account")
        self.assertGreater(result["targets"][0]["score"], result["targets"][1]["score"])
        self.assertGreater(result["targets"][0]["confidence"], 0.9)
        self.assertIn("source-to-runtime dataflow correlation", result["targets"][0]["reasons"])


if __name__ == "__main__":
    unittest.main()
