import unittest
from maher_bounty.report_evidence import build_evidence_report

class EvidenceConfidenceGradingTests(unittest.TestCase):
    def test_report_exposes_chain_strength_and_weakest_hop(self):
        provenance={"chain_count":1,"chains":[{"id":"prov:1","start":"route:1","end":"fn:2","score":0.855,"evidence_kinds":["route","code_function"],"hops":[{"from":"route:1","to":"fn:1","relation":"implemented_by","confidence":0.95},{"from":"fn:1","to":"fn:2","relation":"flow_calls","confidence":0.9}]}]}
        priorities={"target_count":1,"targets":[{"key":"route:1","score":91.0,"confidence":0.92,"reasons":["confidence-weighted interprocedural dataflow"]}]}
        report=build_evidence_report(priorities=priorities,provenance=provenance)
        self.assertEqual(report["schema_version"],"1.1")
        item=report["items"][0]
        self.assertEqual(item["weakest_hop_confidence"],0.9)
        self.assertEqual(item["confidence_grade"],"high")
        self.assertGreater(item["combined_confidence"],item["confidence"])
        self.assertEqual(report["summary"]["confidence_grades"]["high"],1)

if __name__=="__main__": unittest.main()
