import tempfile
import unittest
from pathlib import Path

from maher_bounty.full_analysis_pipeline import analyze_full
from maher_bounty.input_validation import validate_ir_documents, require_valid_ir
from maher_bounty.readiness_gate import evaluate_readiness


class ReleaseIntegrationTests(unittest.TestCase):
    def fn(self,fid,lang,file,name,calls=(),reads=(),writes=(),routes=()):
        return {"id":fid,"language":lang,"file":file,"name":name,"line":1,"async_function":False,"parameters":[],"calls":list(calls),"reads":list(reads),"writes":list(writes),"complexity":1,"route_bindings":list(routes)}

    def test_full_pipeline_static_runtime_and_artifacts(self):
        py={"language":"python","functions":[self.fn("entry","python","svc/api.py","entry",("lookup",),("account.id",),(),({"kind":"http_route","path":"/account"},)),self.fn("primary","python","svc/store.py","lookup",(),("account.id",),("db.account",),({"kind":"http_route","path":"/account"},))]}
        go={"language":"go","functions":[self.fn("secondary","go","other/cache.go","lookup",(),(),("cache.account",))]}
        runtime={"protocols":{"signals":[{"protocol":"graphql","metadata":{"url":"https://api.example.test/account"}}]}}
        require_valid_ir(py,go)
        with tempfile.TemporaryDirectory() as td:
            result=analyze_full(py,go,runtime=runtime,out_dir=td)
            self.assertTrue(result["ready"])
            self.assertEqual(result["semantic"]["resolution_count"],1)
            self.assertIn("db.account",result["flow"]["functions"]["entry"]["transitive_writes"])
            self.assertGreaterEqual(result["runtime_fusion"]["match_count"],1)
            for name in ("unified-ir.json","semantic-resolution.json","interprocedural-flow.json","analysis-coverage.json","coverage-gate.json","static-runtime-fusion.json","full-analysis-summary.json"):
                self.assertTrue((Path(td)/name).exists(),name)

    def test_hardening_rejects_duplicate_ids_and_bad_shapes(self):
        dup={"functions":[self.fn("x","python","a.py","a"),self.fn("x","go","b.go","b")]}
        self.assertFalse(validate_ir_documents(dup)["passed"])
        self.assertFalse(validate_ir_documents({"functions":"bad"})["passed"])
        with self.assertRaises(ValueError): require_valid_ir(dup)

    def test_readiness_gate_fails_closed(self):
        benchmark={"failed":0,"quality_gate":{"passed":True},"results":[],"capability_quality":{}}
        analysis={"ready":False,"coverage_gate":{"passed":False}}
        self.assertFalse(evaluate_readiness(benchmark=benchmark,analysis=analysis)["passed"])


if __name__=="__main__":unittest.main()
