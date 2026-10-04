import unittest

from maher_bounty.semantic_analysis import build_semantic_model
from maher_bounty.unified_ir import merge_ir


class SemanticIRIntegrationTests(unittest.TestCase):
    def test_semantics_resolve_ambiguous_cross_language_names(self):
        doc={"functions":[
            {"id":"fn:caller","language":"java","file":"Users.java","name":"getUser","line":1,"parameters":["id"],"calls":["loadUser"],"reads":["id"],"writes":[],"complexity":2,"route_bindings":[{"path":"/users/{id}"}]},
            {"id":"fn:java","language":"java","file":"Users.java","name":"loadUser","line":5,"parameters":["id"],"calls":[],"reads":["id"],"writes":[],"complexity":1,"route_bindings":[]},
            {"id":"fn:cs","language":"csharp","file":"Other.cs","name":"loadUser","line":5,"parameters":["id"],"calls":[],"reads":[],"writes":[],"complexity":1,"route_bindings":[]},
        ]}
        baseline=merge_ir(doc)
        self.assertEqual(len(baseline["call_edges"]),0)
        self.assertEqual(len(baseline["unresolved_calls"]),1)

        semantics=build_semantic_model(baseline)
        enriched=merge_ir(doc,semantic_model=semantics)
        self.assertEqual(enriched["schema_version"],"1.3")
        self.assertEqual(len(enriched["call_edges"]),1)
        edge=enriched["call_edges"][0]
        self.assertEqual(edge["to"],"fn:java")
        self.assertEqual(edge["resolution"],"semantic")
        self.assertGreater(edge["confidence"],0.7)


if __name__=="__main__":
    unittest.main()
