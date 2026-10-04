import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark
from maher_bounty.benchmark_regression import regression_summary, result_fingerprint


class BenchmarkRegressionTests(unittest.TestCase):
    def test_semantic_fingerprint_is_stable_across_repeated_runs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            first=run_benchmark(root/"run-a")
            second=run_benchmark(root/"run-b")
            regression=regression_summary(first,second)
            self.assertEqual(first["case_count"],126)
            self.assertEqual(second["case_count"],126)
            self.assertTrue(first["quality_gate"]["passed"])
            self.assertTrue(second["quality_gate"]["passed"])
            self.assertTrue(regression["stable"])
            self.assertEqual(result_fingerprint(first),result_fingerprint(second))

    def test_fingerprint_changes_when_semantics_change(self):
        a={"results":[{"name":"x","passed":True,"checks":{"a":True},"classification":{"expected_signal":False,"observed_signal":False},"observed":{"records":1}}]}
        b={"results":[{"name":"x","passed":False,"checks":{"a":False},"classification":{"expected_signal":False,"observed_signal":True},"observed":{"records":1}}]}
        self.assertNotEqual(result_fingerprint(a),result_fingerprint(b))


if __name__=="__main__":
    unittest.main()
