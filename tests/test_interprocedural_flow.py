import unittest
from maher_bounty.interprocedural_flow import build_flow_graph, trace_variable


class InterproceduralFlowTests(unittest.TestCase):
    def test_propagates_reads_and_writes_through_calls(self):
        ir={"functions":[
            {"id":"a","reads":["request.user"],"writes":[]},
            {"id":"b","reads":[],"writes":["db.account"]},
            {"id":"c","reads":[],"writes":[]},
        ],"call_edges":[{"from":"a","to":"b"},{"from":"b","to":"c"}]}
        result=build_flow_graph(ir)
        self.assertIn("db.account",result["functions"]["a"]["transitive_writes"])
        self.assertIn("db.account",result["functions"]["b"]["transitive_writes"])
        self.assertIn("request.user",result["functions"]["a"]["transitive_reads"])

    def test_cycle_reaches_fixpoint(self):
        ir={"functions":[{"id":"a","reads":["x"],"writes":[]},{"id":"b","reads":[],"writes":["y"]}],"call_edges":[{"from":"a","to":"b"},{"from":"b","to":"a"}]}
        result=build_flow_graph(ir)
        self.assertIn("x",result["functions"]["b"]["transitive_reads"])
        self.assertIn("y",result["functions"]["a"]["transitive_writes"])

    def test_long_call_chain_propagates_in_few_fixpoint_rounds(self):
        count = 100
        ir = {
            "functions": [{"id": str(i), "reads": [f"v{i}"], "writes": []} for i in range(count)],
            "call_edges": [{"from": str(i), "to": str(i + 1)} for i in range(count - 1)],
        }
        result = build_flow_graph(ir)
        self.assertIn(f"v{count - 1}", result["functions"]["0"]["transitive_reads"])
        self.assertLessEqual(result["fixpoint_rounds"], 3)

    def test_trace_variable(self):
        ir={"functions":[{"id":"a","reads":["token"],"writes":[]}],"call_edges":[]}
        result=trace_variable(ir,"token")
        self.assertEqual(result["function_count"],1)
        self.assertTrue(result["functions"][0]["reads"])


if __name__=="__main__":unittest.main()
