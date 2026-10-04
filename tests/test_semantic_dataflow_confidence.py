import unittest

from maher_bounty.interprocedural_dataflow import build_interprocedural_dataflow


class SemanticDataflowConfidenceTests(unittest.TestCase):
    def test_call_confidence_controls_downstream_flow_confidence(self):
        ir={"functions":[
            {"id":"fn:a","language":"java","file":"A.java","name":"route","parameters":["id"],"calls":["load"],"reads":["id"],"writes":[],"complexity":1,"route_bindings":[{"path":"/x/{id}"}]},
            {"id":"fn:b","language":"java","file":"A.java","name":"load","parameters":["id"],"calls":[],"reads":["id"],"writes":[],"complexity":1,"route_bindings":[]},
        ],"call_edges":[{"from":"fn:a","to":"fn:b","kind":"calls","symbol":"load","confidence":0.8,"resolution":"semantic"}]}
        graph=build_interprocedural_dataflow(ir)
        self.assertEqual(graph["schema_version"],"1.2")
        call=next(e for e in graph["edges"] if e["kind"]=="calls")
        self.assertEqual(call["confidence"],0.8)
        self.assertEqual(call["provenance"]["resolution"],"semantic")
        flows=[e for e in graph["edges"] if e["kind"]=="argument_flow"]
        self.assertTrue(flows)
        self.assertTrue(all(e["confidence"] < call["confidence"] for e in flows))
        reached=graph["reachable_from_routes"]["fn:a"]
        target=next(x for x in reached if x["node"]=="fn:b")
        self.assertEqual(target["confidence"],0.8)


if __name__=="__main__":
    unittest.main()
