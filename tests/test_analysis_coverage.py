import unittest
from maher_bounty.analysis_coverage import coverage_gate, measure_analysis_coverage
from maher_bounty.interprocedural_flow import build_flow_graph


class AnalysisCoverageTests(unittest.TestCase):
    def test_high_resolution_ir_passes(self):
        ir={"functions":[{"id":"a","language":"python","calls":["b"],"reads":["x"],"writes":[],"route_bindings":[]},{"id":"b","language":"go","calls":[],"reads":[],"writes":["y"],"route_bindings":[]}],"call_edges":[{"from":"a","to":"b"}],"unresolved_calls":[]}
        flow=build_flow_graph(ir); metrics=measure_analysis_coverage(ir,flow)
        self.assertEqual(metrics["language_count"],2)
        self.assertEqual(metrics["call_resolution_rate"],1.0)
        self.assertEqual(metrics["flow_coverage"],1.0)
        self.assertTrue(coverage_gate(metrics)["passed"])

    def test_low_resolution_fails(self):
        ir={"functions":[{"id":"a","language":"python","calls":["x","y"],"reads":[],"writes":[],"route_bindings":[]}],"call_edges":[],"unresolved_calls":[{"symbol":"x"},{"symbol":"y"}]}
        metrics=measure_analysis_coverage(ir,build_flow_graph(ir))
        self.assertFalse(coverage_gate(metrics)["passed"])


if __name__=="__main__":unittest.main()
