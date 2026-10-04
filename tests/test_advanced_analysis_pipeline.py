import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.advanced_analysis_pipeline import analyze_ir_documents


class AdvancedAnalysisPipelineTests(unittest.TestCase):
    def fn(self, fid, lang, file, name, calls=(), reads=(), writes=(), routes=()):
        return {"id":fid,"language":lang,"file":file,"name":name,"line":1,"async_function":False,"parameters":[],"calls":list(calls),"reads":list(reads),"writes":list(writes),"complexity":1,"route_bindings":list(routes)}

    def test_cross_file_cross_language_pipeline(self):
        py={"language":"python","functions":[self.fn("py:entry","python","api.py","entry",("lookup",),("request.user",),(),({"kind":"http_route","path":"/account"},))]}
        go={"language":"go","functions":[self.fn("go:lookup","go","store.go","lookup",(),(),("db.account",))]}
        result=analyze_ir_documents(py,go)
        self.assertTrue(result["ready"])
        self.assertEqual(result["coverage"]["call_resolution_rate"],1.0)
        self.assertIn("db.account",result["flow"]["functions"]["py:entry"]["transitive_writes"])

    def test_ambiguous_cross_file_call_fails_resolution_gate(self):
        caller={"language":"python","functions":[self.fn("a","python","a.py","entry",("lookup",))]}
        targets={"language":"mixed","functions":[self.fn("b","go","b.go","lookup"),self.fn("c","javascript_typescript","c.ts","lookup")]}
        result=analyze_ir_documents(caller,targets,min_resolution=.60)
        self.assertFalse(result["ready"])
        self.assertEqual(len(result["ir"]["unresolved_calls"]),1)
        self.assertEqual(result["semantic_model"]["deferred_count"],1)

    def test_automatic_semantic_resolution_recovers_clear_winner(self):
        caller={"language":"python","functions":[self.fn("a","python","svc/api.py","entry",("lookup",),("account.id",),(),({"kind":"http_route","path":"/account"},))]}
        targets={"language":"mixed","functions":[self.fn("b","python","svc/store.py","lookup",reads=("account.id",),writes=("db.primary",),routes=({"kind":"http_route","path":"/account"},)),self.fn("c","go","x/cache.go","lookup",writes=("cache.secondary",))]}
        result=analyze_ir_documents(caller,targets)
        self.assertTrue(result["semantic_generated"])
        self.assertEqual(result["semantic_model"]["resolution_count"],1)
        self.assertEqual(result["ir"]["call_edges"][0]["to"],"b")
        self.assertIn("db.primary",result["flow"]["functions"]["a"]["transitive_writes"])

    def test_runtime_fusion_is_part_of_pipeline(self):
        doc={"language":"python","functions":[self.fn("a","python","api.py","entry",reads=("request.user",),writes=("db.account",),routes=({"kind":"http_route","path":"/account"},))]}
        runtime={"signals":[{"protocol":"http","metadata":{"url":"https://api.example.test/account"}}]}
        result=analyze_ir_documents(doc,runtime_result=runtime,min_resolution=0)
        self.assertEqual(result["runtime_fusion"]["match_count"],1)
        self.assertEqual(result["runtime_fusion"]["matches"][0]["function"],"a")

    def test_explicit_semantic_model_still_supported(self):
        caller={"language":"python","functions":[self.fn("a","python","a.py","entry",("lookup",))]}
        targets={"language":"mixed","functions":[self.fn("b","go","b.go","lookup"),self.fn("c","javascript_typescript","c.ts","lookup")]}
        semantic={"call_resolutions":[{"caller":"a","symbol":"lookup","resolved":"b","confidence":.96}]}
        result=analyze_ir_documents(caller,targets,semantic_model=semantic)
        self.assertEqual(result["ir"]["call_edges"][0]["to"],"b")
        self.assertFalse(result["semantic_generated"])

    def test_writes_deterministic_artifacts(self):
        doc={"language":"python","functions":[self.fn("a","python","a.py","entry",reads=("x",))]}
        with tempfile.TemporaryDirectory() as td:
            result=analyze_ir_documents(doc,out_dir=td,min_resolution=0)
            self.assertTrue(result["ready"])
            for name in ("unified-ir.json","semantic-resolution.json","interprocedural-flow.json","analysis-coverage.json","coverage-gate.json","advanced-analysis-summary.json"):
                p=Path(td)/name; self.assertTrue(p.exists(),name); json.loads(p.read_text(encoding="utf-8"))


if __name__=="__main__":unittest.main()
