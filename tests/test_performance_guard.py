import unittest
from maher_bounty.performance_guard import compare_performance, measure


class PerformanceGuardTests(unittest.TestCase):
    def test_measure_returns_time_memory_and_result(self):
        result=measure(lambda:sum(range(1000)))
        self.assertEqual(result["result"],499500)
        self.assertGreaterEqual(result["elapsed_seconds"],0)
        self.assertGreaterEqual(result["peak_bytes"],0)

    def test_regression_limits(self):
        base={"elapsed_seconds":1.0,"peak_bytes":1000}
        self.assertTrue(compare_performance({"elapsed_seconds":1.4,"peak_bytes":1400},base)["passed"])
        self.assertFalse(compare_performance({"elapsed_seconds":1.6,"peak_bytes":1400},base)["passed"])
        self.assertFalse(compare_performance({"elapsed_seconds":1.4,"peak_bytes":1600},base)["passed"])


if __name__=="__main__":unittest.main()
