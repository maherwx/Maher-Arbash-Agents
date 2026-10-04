import unittest

from maher_bounty.knowledge_graph import build_application_graph
from maher_bounty.adaptive_prioritizer import rank_analysis_targets


class DataflowGraphIntegrationTests(unittest.TestCase):
    def test_dataflow_enters_graph_and_priority_model(self):
        inventory={"hosts":[{"value":"api.test"}],"endpoints":[{"value":"https://api.test/users/{id}"}]}
        flow={
            "nodes":[
                {"id":"fn:route","kind":"function","language":"python","file":"api.py","name":"get_user","line":10,"complexity":4,"route_bindings":[{"method":"GET","path":"/users/{id}"}]},
                {"id":"fn:route:param:0:id","kind":"parameter","name":"id"},
                {"id":"fn:load","kind":"function","language":"java","file":"Users.java","name":"load_user","line":20,"complexity":2},
            ],
            "edges":[
                {"source":"fn:route:param:0:id","target":"fn:route","kind":"parameter_of","symbol":"id","confidence":1.0,"provenance":{}},
                {"source":"fn:route","target":"fn:load","kind":"calls","symbol":"load_user","confidence":0.99,"provenance":{"source":"unified_ir"}},
                {"source":"fn:route:param:0:id","target":"fn:load","kind":"argument_flow","symbol":"id","confidence":0.88,"provenance":{"reason":"matching parameter"}},
            ],
            "reachable_from_routes":{"fn:route":[{"node":"fn:load","depth":1,"via":"calls","confidence":0.99},{"node":"fn:route:param:0:id","depth":1,"via":"argument_flow","confidence":0.88}]},
        }
        graph=build_application_graph(inventory,dataflow_graph=flow)
        kinds=graph["stats"]["kinds"]
        self.assertEqual(graph["schema_version"],"2.1")
        self.assertEqual(kinds["code_function"],2)
        relations={e["relation"] for e in graph["edges"]}
        self.assertIn("implemented_by",relations)
        self.assertIn("flow_argument_flow",relations)

        ranked=rank_analysis_targets(dataflow_graph=flow)
        self.assertEqual(ranked["target_count"],1)
        self.assertIn("interprocedural route-reachable dataflow",ranked["targets"][0]["reasons"])
        self.assertGreater(ranked["targets"][0]["score"],0)


if __name__=="__main__":
    unittest.main()
