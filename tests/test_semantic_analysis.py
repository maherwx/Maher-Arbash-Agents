import unittest

from maher_bounty.semantic_analysis import build_semantic_model


class SemanticAnalysisTests(unittest.TestCase):
    def test_resolves_same_file_symbol_and_ranks_hot_functions(self):
        ir={"functions":[
            {"id":"fn:a","language":"java","file":"Users.java","name":"getUser","line":10,"parameters":["id"],"calls":["loadUser"],"reads":["id"],"writes":[],"complexity":4,"route_bindings":[{"path":"/users/{id}"}]},
            {"id":"fn:b","language":"java","file":"Users.java","name":"loadUser","line":20,"parameters":["id"],"calls":[],"reads":["id"],"writes":["user"],"complexity":2,"route_bindings":[]},
            {"id":"fn:c","language":"csharp","file":"Other.cs","name":"loadUser","line":5,"parameters":["id"],"calls":[],"reads":[],"writes":[],"complexity":1,"route_bindings":[]},
        ]}
        model=build_semantic_model(ir)
        self.assertEqual(model["symbol_count"],3)
        resolution=model["call_resolutions"][0]
        self.assertEqual(resolution["resolved"],"fn:b")
        self.assertGreater(resolution["candidates"][0]["confidence"],resolution["candidates"][1]["confidence"])
        self.assertEqual(model["hot_functions"][0]["function"],"fn:a")


if __name__=="__main__":
    unittest.main()
