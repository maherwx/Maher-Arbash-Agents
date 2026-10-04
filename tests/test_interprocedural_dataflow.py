import unittest

from maher_bounty.interprocedural_dataflow import build_interprocedural_dataflow, summarize_flow_paths


class InterproceduralDataflowTests(unittest.TestCase):
    def test_builds_argument_and_call_flow_across_functions(self):
        ir={
            "functions":[
                {
                    "id":"fn:route","language":"python","file":"api.py","name":"get_user","line":1,
                    "async_function":True,"parameters":["user_id"],"calls":["load_user"],
                    "reads":["user_id"],"writes":[],"complexity":2,
                    "route_bindings":[{"kind":"http_route","method":"GET","path":"/users/{id}"}],
                },
                {
                    "id":"fn:loader","language":"java","file":"Users.java","name":"load_user","line":10,
                    "async_function":False,"parameters":["user_id"],"calls":[],
                    "reads":["user_id"],"writes":["user"],"complexity":1,"route_bindings":[],
                },
            ],
            "call_edges":[{"from":"fn:route","to":"fn:loader","kind":"calls","symbol":"load_user"}],
        }
        graph=build_interprocedural_dataflow(ir)
        kinds={e["kind"] for e in graph["edges"]}
        self.assertIn("calls",kinds)
        self.assertIn("argument_flow",kinds)
        self.assertEqual(graph["route_entrypoints"],["fn:route"])
        self.assertGreaterEqual(len(graph["reachable_from_routes"]["fn:route"]),1)
        summary=summarize_flow_paths(graph)
        self.assertGreaterEqual(summary["qualified_edge_count"],3)
        self.assertEqual(summary["route_entrypoint_count"],1)


if __name__=="__main__":
    unittest.main()
