import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_default_benchmark_passes_and_reports_quality(self):
        with tempfile.TemporaryDirectory() as td:
            result=run_benchmark(Path(td)/"bench")
            self.assertEqual(result["case_count"],8)
            self.assertEqual(result["failed"],0)
            self.assertEqual(result["pass_rate"],1.0)
            self.assertEqual(result["schema_version"],"1.2")
            for metric in ("precision","recall","specificity","false_positive_rate"):
                self.assertIn(metric,result["quality"])
            self.assertGreaterEqual(result["quality"]["precision"],0.8)
            self.assertGreaterEqual(result["quality"]["recall"],0.8)
            baseline=next(x for x in result["results"] if x["name"]=="baseline_http")
            ordinary=next(x for x in result["results"] if x["name"]=="ordinary_json_api")
            same=next(x for x in result["results"] if x["name"]=="identity_same_outcome")
            workflow=next(x for x in result["results"] if x["name"]=="identity_workflow_divergence")
            self.assertFalse(baseline["classification"]["observed_signal"])
            self.assertFalse(ordinary["classification"]["observed_signal"])
            self.assertEqual(same["observed"]["workflow_divergences"],0)
            self.assertGreaterEqual(workflow["observed"]["workflow_divergences"],1)
            self.assertTrue((Path(td)/"bench"/"benchmark-summary.json").exists())


if __name__=="__main__":
    unittest.main()
