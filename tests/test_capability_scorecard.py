import unittest
from maher_bounty.capability_scorecard import build_scorecard


class CapabilityScorecardTests(unittest.TestCase):
    def test_scorecard_exposes_every_core_capability(self):
        summary={"results":[
            {"name":"graphql_signal","passed":True,"classification":{"expected_signal":True}},
            {"name":"grpc_signal","passed":True,"classification":{"expected_signal":True}},
            {"name":"openapi_signal","passed":True,"classification":{"expected_signal":True}},
            {"name":"websocket_signal","passed":True,"classification":{"expected_signal":True}},
            {"name":"workflow_divergent","passed":True,"classification":{"expected_signal":True}},
            {"name":"baseline_http","passed":True,"classification":{"expected_signal":False}},
        ],"capability_quality":{
            k:{"precision":1.0,"recall":1.0,"specificity":1.0} for k in ("graphql","grpc","openapi","websocket","workflow_identity","generic_http")}}
        result=build_scorecard(summary)
        self.assertEqual(len(result["capabilities"]),6)
        self.assertEqual(result["overall_score"],100.0)
        self.assertEqual(result["minimum_capability_score"],100.0)

    def test_weak_capability_is_visible(self):
        summary={"results":[{"name":"graphql_signal","passed":False,"classification":{"expected_signal":True}}],"capability_quality":{"graphql":{"precision":.5,"recall":.5,"specificity":1.0}}}
        result=build_scorecard(summary)
        self.assertLess(result["capabilities"]["graphql"]["score"],70)
        self.assertLess(result["minimum_capability_score"],70)


if __name__=="__main__":unittest.main()
