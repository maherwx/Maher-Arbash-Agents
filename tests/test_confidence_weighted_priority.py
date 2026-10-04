import unittest

from maher_bounty.adaptive_prioritizer import rank_analysis_targets


class ConfidenceWeightedPriorityTests(unittest.TestCase):
    def _graph(self, confidence):
        return {"nodes":[{"id":"fn:r","kind":"function","name":"route","route_bindings":[{"path":"/users/{id}"}]}],"reachable_from_routes":{"fn:r":[{"node":"fn:x","depth":1,"via":"calls","confidence":confidence},{"node":"p:x","depth":2,"via":"argument_flow","confidence":confidence*0.8}]}}

    def test_stronger_semantic_paths_rank_higher(self):
        strong=rank_analysis_targets(dataflow_graph=self._graph(0.95))["targets"][0]
        weak=rank_analysis_targets(dataflow_graph=self._graph(0.70))["targets"][0]
        self.assertGreater(strong["score"],weak["score"])
        self.assertGreater(strong["confidence"],weak["confidence"])
        self.assertIn("confidence-weighted interprocedural dataflow",strong["reasons"])
        evidence=strong["evidence"]["interprocedural_dataflow"]
        self.assertIn("mean_path_confidence",evidence)
        self.assertIn("evidence_strength",evidence)


if __name__=="__main__":
    unittest.main()
