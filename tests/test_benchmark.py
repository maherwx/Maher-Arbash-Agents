import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_default_benchmark_passes_and_reports_quality(self):
        with tempfile.TemporaryDirectory() as td:
            result=run_benchmark(Path(td)/"bench")
            self.assertEqual(result["case_count"],3)
            self.assertEqual(result["failed"],0)
            self.assertEqual(result["pass_rate"],1.0)
            self.assertEqual(result["schema_version"],"1.1")
            self.assertIn("precision",result["quality"])
            self.assertIn("recall",result["quality"])
            self.assertIn("specificity",result["quality"])
            workflow=next(x for x in result["results"] if x["name"]=="identity_workflow_divergence")
            self.assertGreaterEqual(workflow["observed"]["workflow_divergences"],1)
            self.assertTrue((Path(td)/"bench"/"benchmark-summary.json").exists())


if __name__=="__main__":
    unittest.main()
