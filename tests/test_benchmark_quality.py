import unittest

from maher_bounty.benchmark_quality import capability_quality, quality_gate


class BenchmarkQualityTests(unittest.TestCase):
    def test_capability_metrics_do_not_hide_false_positive(self):
        rows = [
            {"name":"graphql_signal","classification":{"expected_signal":True,"observed_signal":True}},
            {"name":"grpc_signal","classification":{"expected_signal":True,"observed_signal":True}},
            {"name":"identity_same_outcome","classification":{"expected_signal":False,"observed_signal":False}},
            {"name":"baseline_http","classification":{"expected_signal":False,"observed_signal":True}},
        ]
        quality = capability_quality(rows)
        self.assertEqual(quality["graphql"]["recall"], 1.0)
        self.assertEqual(quality["generic_http"]["fp"], 1)
        self.assertEqual(quality["generic_http"]["false_positive_rate"], 1.0)

    def test_quality_gate(self):
        good={"failed":0,"quality":{"precision":0.95,"recall":0.90,"false_positive_rate":0.05}}
        bad={"failed":1,"quality":{"precision":0.70,"recall":0.90,"false_positive_rate":0.30}}
        self.assertTrue(quality_gate(good)["passed"])
        self.assertFalse(quality_gate(bad)["passed"])


if __name__ == "__main__":
    unittest.main()
