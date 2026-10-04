import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_default_benchmark_passes_and_reports_quality(self):
        with tempfile.TemporaryDirectory() as td:
            result=run_benchmark(Path(td)/"bench")
            self.assertEqual(result["case_count"],126)
            self.assertEqual(result["failed"],0)
            self.assertEqual(result["pass_rate"],1.0)
            self.assertEqual(result["schema_version"],"1.9")
            self.assertGreaterEqual(result["quality"]["precision"],0.90)
            self.assertGreaterEqual(result["quality"]["recall"],0.90)
            self.assertLessEqual(result["quality"]["false_positive_rate"],0.10)
            self.assertTrue(result["quality_gate"]["passed"])
            for capability in ("graphql","grpc","openapi","websocket","workflow_identity","generic_http"):
                self.assertIn(capability,result["capability_quality"])
            for capability in ("graphql","grpc","openapi","websocket","workflow_identity"):
                metrics=result["capability_quality"][capability]
                if metrics["positive_support"]:
                    self.assertGreaterEqual(metrics["recall"],0.90)
                    self.assertGreaterEqual(metrics["precision"],0.90)
            scaled=[x for x in result["results"] if x["name"].startswith("scaled_negative_")]
            positives=[x for x in result["results"] if x["name"].startswith("positive_")]
            wf_equal=[x for x in result["results"] if x["name"].startswith("workflow_equal_")]
            wf_div=[x for x in result["results"] if x["name"].startswith("workflow_divergent_")]
            stress_benign=[x for x in result["results"] if x["name"].startswith("stress_benign_")]
            stress_mixed=[x for x in result["results"] if x["name"].startswith("stress_mixed_")]
            noise=[x for x in result["results"] if x["name"].startswith("noise_vocab_")]
            self.assertEqual(len(scaled),36)
            self.assertEqual(len(positives),28)
            self.assertEqual(len(wf_equal),10)
            self.assertEqual(len(wf_div),10)
            self.assertEqual(len(stress_benign),6)
            self.assertEqual(len(stress_mixed),6)
            self.assertEqual(len(noise),16)
            self.assertTrue(all(x["passed"] for x in scaled+positives+wf_equal+wf_div+stress_benign+stress_mixed+noise))
            self.assertTrue((Path(td)/"bench"/"benchmark-summary.json").exists())


if __name__=="__main__":
    unittest.main()
