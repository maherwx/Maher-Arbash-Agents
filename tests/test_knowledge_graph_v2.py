import unittest

from maher_bounty.knowledge_graph import build_application_graph


class KnowledgeGraphV2Tests(unittest.TestCase):
    def test_correlates_route_protocol_behavior_and_anomaly(self):
        inventory = {"hosts": [{"value": "api.example.test"}], "endpoints": [{"value": "https://api.example.test/graphql"}]}
        protocols = {"signals": [{"protocol": "graphql", "source": "traffic:0", "key": "Viewer", "confidence": 0.98, "metadata": {"url": "https://api.example.test/graphql"}}]}
        behavior = {"families": [{"route_shape": "api.example.test/graphql", "observations": 3, "unique_behaviors": 2, "methods": ["POST"], "statuses": [200, 403], "behavior_variance": 0.6667}]}
        anomalies = {"anomalies": [{"host": "api.example.test", "method": "POST", "route_shape": "/graphql", "anomaly_score": 75, "reasons": ["status divergence"], "observations": 3}]}
        graph = build_application_graph(inventory, protocol_intelligence=protocols, behavior_model=behavior, anomalies=anomalies)
        kinds = graph["stats"]["kinds"]
        self.assertEqual(kinds["host"], 1)
        self.assertEqual(kinds["route"], 1)
        self.assertEqual(kinds["protocol_signal"], 1)
        self.assertEqual(kinds["behavior_family"], 1)
        self.assertEqual(kinds["behavioral_anomaly"], 1)
        relations = {e["relation"] for e in graph["edges"]}
        self.assertTrue({"exposes", "uses_protocol", "has_behavior", "exhibits"}.issubset(relations))
        self.assertGreaterEqual(graph["hubs"][0]["degree"], 2)


if __name__ == "__main__":
    unittest.main()
