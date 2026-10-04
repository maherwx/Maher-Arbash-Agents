import tempfile
import unittest
from pathlib import Path

from maher_bounty.python_ast_intelligence import analyze_python_ast


class PythonAstIntelligenceTests(unittest.TestCase):
    def test_builds_structural_function_and_call_models(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "api.py").write_text(
                'from fastapi import FastAPI\n'
                'app=FastAPI()\n'
                'def load_user(user_id):\n'
                '    return db.query(user_id)\n'
                '@app.get("/users/{user_id}")\n'
                'async def get_user(user_id):\n'
                '    if not user_id:\n'
                '        return None\n'
                '    try:\n'
                '        user=load_user(user_id)\n'
                '    except Exception:\n'
                '        return None\n'
                '    return user\n',
                encoding="utf-8",
            )
            result = analyze_python_ast(root)
            self.assertEqual(result["function_count"], 2)
            self.assertEqual(len(result["route_functions"]), 1)
            route = result["route_functions"][0]
            self.assertEqual(route["function"], "get_user")
            self.assertGreaterEqual(route["complexity"], 3)
            edges = {(e["caller"], e["callee"]) for e in result["call_edges"]}
            self.assertIn(("api.py:get_user", "load_user"), edges)
            fn = next(x for x in result["functions"] if x["name"] == "get_user")
            self.assertTrue(fn["async_function"])
            self.assertIn("user_id", fn["reads"])


if __name__ == "__main__":
    unittest.main()
