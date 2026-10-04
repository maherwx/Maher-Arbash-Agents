import unittest
from maher_bounty.rc_readiness import assess_release_candidate


class RCReadinessTests(unittest.TestCase):
    def test_all_gates_ready(self):
        result=assess_release_candidate(analysis={"ready":True,"coverage_gate":{"passed":True}},artifacts={"passed":True},benchmark={"failed":0,"quality_gate":{"passed":True}},performance={"passed":True})
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"],"ready")
        self.assertEqual(result["failed_checks"],[])

    def test_any_failed_gate_blocks_release(self):
        result=assess_release_candidate(analysis={"ready":True,"coverage_gate":{"passed":True}},artifacts={"passed":False},benchmark={"failed":0,"quality_gate":{"passed":True}},performance={"passed":True})
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"],"not_ready")
        self.assertIn("artifact_integrity",result["failed_checks"])


if __name__=="__main__":unittest.main()
