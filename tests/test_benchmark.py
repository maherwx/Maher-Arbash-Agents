import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_default_benchmark_passes_and_reports_quality(self):
        with tempfile.TemporaryDirectory() as td:
            result=run_benchmark(Path(td)/"bench")
            self.assertEqual(result["case_count"],78)
            self.assertEqual(result["failed"],0)
            self.assertEqual(result["pass_rate"],1.0)
            self.assertEqual(result["schema_version"],"1.6")
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
            self.assertEqual(len(scaled),36)
            self.assertEqual(len(positives),28)
            self.assertTrue(all(x["passed"] for x in scaled))
            self.assertTrue(all(x["passed"] for x in positives))
            self.assertTrue((Path(td)/"bench"/"benchmark-summary.json").exists())


if __name__=="__main__":
    unittest.main()
