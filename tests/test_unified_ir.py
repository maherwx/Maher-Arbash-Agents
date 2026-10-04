import unittest

from maher_bounty.unified_ir import from_python_ast, from_jsts_ast, merge_ir


class UnifiedIRTests(unittest.TestCase):
    def test_merges_python_and_jsts_functions_and_resolves_calls(self):
        py={
            "functions":[
                {"file":"api.py","name":"load_user","line":1,"async_function":False,"parameters":["id"],"calls":[],"reads":["id"],"writes":[],"complexity":1},
                {"file":"api.py","name":"get_user","line":5,"async_function":True,"parameters":["id"],"calls":["load_user"],"reads":["id"],"writes":[],"complexity":2},
            ],
            "route_functions":[{"file":"api.py","function":"get_user","decorators":["app.get"]}],
        }
        js={
            "functions":[
                {"file":"client.ts","name":"fetchUser","line":1,"async":True,"params":["id"],"calls":["load_user"],"reads":["id"],"writes":[],"complexity":1}
            ],
            "route_handlers":[{"file":"client.ts","line":1,"method":"GET","path":"/users/:id"}],
        }
        merged=merge_ir(from_python_ast(py), from_jsts_ast(js))
        self.assertEqual(merged["function_count"],3)
        self.assertEqual(set(merged["languages"]),{"python","javascript_typescript"})
        self.assertEqual(merged["route_function_count"],2)
        edges={(e["symbol"], e["kind"]) for e in merged["call_edges"]}
        self.assertIn(("load_user","calls"),edges)
        self.assertTrue(all(fn["id"].startswith("fn:") for fn in merged["functions"]))


if __name__=="__main__":
    unittest.main()
