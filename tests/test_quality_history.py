import unittest
from maher_bounty.quality_history import compare_quality


class QualityHistoryTests(unittest.TestCase):
    def test_equal_or_better_quality_passes(self):
        baseline={"quality":{"precision":.90,"recall":.91,"specificity":.95,"false_positive_rate":.05}}
        current={"quality":{"precision":.94,"recall":.92,"specificity":.96,"false_positive_rate":.04}}
        self.assertTrue(compare_quality(current,baseline)["passed"])

    def test_precision_regression_fails(self):
        baseline={"quality":{"precision":.95,"recall":.90,"specificity":.95,"false_positive_rate":.05}}
        current={"quality":{"precision":.94,"recall":.90,"specificity":.95,"false_positive_rate":.05}}
        result=compare_quality(current,baseline)
        self.assertFalse(result["passed"])
        self.assertFalse(result["metrics"]["precision"]["passed"])

    def test_fpr_regression_fails(self):
        baseline={"quality":{"precision":.95,"recall":.95,"specificity":.95,"false_positive_rate":.03}}
        current={"quality":{"precision":.95,"recall":.95,"specificity":.95,"false_positive_rate":.04}}
        self.assertFalse(compare_quality(current,baseline)["passed"])


if __name__=="__main__":
    unittest.main()
