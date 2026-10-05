import json
import os
import tempfile
import unittest
from pathlib import Path

from maher_bounty.workflow_benchmark import run_workflow_benchmark


class LiveWorkflowBenchmarkTests(unittest.TestCase):
    def check_engine(self, engine):
        previous = {key: value for key, value in os.environ.items() if key.startswith("MAHER_BENCH_")}
        with tempfile.TemporaryDirectory() as td:
            result = run_workflow_benchmark(td, engine=engine)
            self.assertTrue(result["quality_gate_passed"], result["results"])
            self.assertEqual(result["case_count"], 8)
            self.assertEqual(result["passed"], 8)
            self.assertEqual(result["quality"]["confirmed_access_detected"], 2)
            self.assertEqual(result["quality"]["false_positive_cases"], 0)
            self.assertEqual(result["quality"]["inconclusive_controls_preserved"], 2)
            self.assertEqual(result, json.loads((Path(td) / "workflow-benchmark.json").read_text()))
            self.assertNotIn("session=", (Path(td) / "workflow-benchmark.json").read_text())
            candidate = next(row for row in result["results"] if row["case"] == "unprotected_state")
            self.assertEqual(candidate["confirmed_findings"], 0)
            self.assertEqual(candidate["candidate_findings"], 1)
            self.assertTrue(candidate["cleanup_verified"])
            self.assertTrue(next(row for row in result["results"] if row["case"] == "protected_state")["cleanup_verified"])
        self.assertEqual(previous, {key: value for key, value in os.environ.items() if key.startswith("MAHER_BENCH_")})

    def test_http_live_access_and_state_quality(self):
        self.check_engine("http")

    @unittest.skipUnless(os.environ.get("MAHER_BROWSER_TESTS") == "1", "actual Chromium benchmark opt-in")
    def test_browser_live_access_and_state_quality(self):
        self.check_engine("browser")

    def test_invalid_engine_rejected(self):
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            run_workflow_benchmark(td, engine="unknown")
