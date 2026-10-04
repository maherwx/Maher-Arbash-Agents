import tempfile
import unittest
from pathlib import Path

from maher_bounty.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_default_benchmark_passes(self):
        with tempfile.TemporaryDirectory() as td:
            result=run_benchmark(Path(td)/"bench")
            self.assertEqual(result["case_count"],2)
            self.assertEqual(result["failed"],0)
            self.assertEqual(result["pass_rate"],1.0)
            self.assertTrue((Path(td)/"bench"/"benchmark-summary.json").exists())


if __name__=="__main__":
    unittest.main()
