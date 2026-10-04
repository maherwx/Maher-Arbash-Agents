import unittest

from maher_bounty.provenance_engine import build_provenance_chains, summarize_provenance
from maher_bounty.report_evidence import build_evidence_report


class ProvenanceReportingTests(unittest.TestCase):
    def test_builds_route_to_code_flow_provenance_chain(self):
        graph = {
            "nodes": [
                {"id":"route:1","kind":"route","path":"/users/{id}"},
                {"id":"fn:1","kind":"code_function","name":"get_user"},
                {"id":"param:1","kind":"code_parameter","name":"id"},
                {"id":"fn:2","kind":"code_function","name":"load_user"},
            ],
            "edges": [
                {"from":"route:1","to":"fn:1","relation":"implemented_by","confidence":0.9},
                {"from":"param:1","to":"fn:1","relation":"flow_parameter_of","confidence":1.0},
                {"from":"fn:1","to":"fn:2","relation":"flow_calls","confidence":0.99},
            ],
        }
        provenance = build_provenance_chains(graph)
        self.assertGreaterEqual(provenance["chain_count"], 1)
        summary = summarize_provenance(provenance)
        self.assertGreaterEqual(summary["strong_chain_count"], 1)

        priorities = {"targets":[{"key":"route:1","score":88.0,"reasons":["interprocedural route-reachable dataflow"]}]}
        report = build_evidence_report(priorities=priorities, provenance=provenance)
        self.assertGreaterEqual(report["item_count"], 1)
        self.assertEqual(report["items"][0]["priority_score"], 88.0)
        self.assertGreaterEqual(len(report["items"][0]["steps"]), 1)


if __name__=="__main__":
    unittest.main()
