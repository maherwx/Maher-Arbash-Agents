import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.advanced_analysis_pipeline import analyze_ir_documents
from maher_bounty.artifact_integrity import validate_artifacts


class ReleaseCandidateHardeningTests(unittest.TestCase):
    def fn(self,fid,name="f",calls=(),reads=(),writes=()):
        return {"id":fid,"language":"python","file":f"{fid}.py","name":name,"line":1,"async_function":False,"parameters":[],"calls":list(calls),"reads":list(reads),"writes":list(writes),"complexity":1,"route_bindings":[]}

    def test_deep_call_chain_reaches_fixpoint(self):
        functions=[]
        for i in range(200):
            calls=(f"f{i+1}",) if i<199 else ()
            functions.append(self.fn(f"id{i}",f"f{i}",calls,writes=("terminal",) if i==199 else ()))
        result=analyze_ir_documents({"language":"python","functions":functions},min_resolution=.99)
        self.assertTrue(result["ready"])
        self.assertIn("terminal",result["flow"]["functions"]["id0"]["transitive_writes"])

    def test_large_cycle_does_not_loop_forever(self):
        functions=[]
        for i in range(100):
            functions.append(self.fn(f"id{i}",f"f{i}",(f"f{(i+1)%100}",),reads=(f"v{i}",)))
        result=analyze_ir_documents({"language":"python","functions":functions},min_resolution=.99)
        self.assertTrue(result["ready"])
        self.assertEqual(len(result["flow"]["functions"]["id0"]["transitive_reads"]),100)

    def test_unicode_metadata_survives_artifacts(self):
        doc={"language":"python","functions":[self.fn("unicode","تحليل_آمن",reads=("مستخدم.معرف",))]}
        with tempfile.TemporaryDirectory() as td:
            analyze_ir_documents(doc,out_dir=td,min_resolution=0)
            raw=(Path(td)/"advanced-analysis-summary.json").read_text(encoding="utf-8")
            self.assertIn("مستخدم.معرف",raw)
            self.assertTrue(validate_artifacts(td)["passed"])

    def test_artifact_integrity_detects_corruption(self):
        doc={"language":"python","functions":[self.fn("a")]}
        with tempfile.TemporaryDirectory() as td:
            analyze_ir_documents(doc,out_dir=td,min_resolution=0)
            self.assertTrue(validate_artifacts(td)["passed"])
            (Path(td)/"unified-ir.json").write_text("{broken",encoding="utf-8")
            check=validate_artifacts(td)
            self.assertFalse(check["passed"])
            bad=[x for x in check["artifacts"] if x["name"]=="unified-ir.json"][0]
            self.assertFalse(bad["valid_json"])

    def test_empty_project_fails_readiness(self):
        result=analyze_ir_documents({"language":"python","functions":[]},min_resolution=0)
        self.assertFalse(result["ready"])
        self.assertFalse(result["coverage_gate"]["checks"]["has_functions"])


if __name__=="__main__":unittest.main()
