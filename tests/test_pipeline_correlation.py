import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.traffic_pipeline import analyze_traffic


class PipelineCorrelationTests(unittest.TestCase):
    def test_pipeline_emits_conservative_correlation_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            har=root/"sample.har"
            har.write_text(json.dumps({"log":{"entries":[{
                "startedDateTime":"2026-01-01T00:00:00Z",
                "request":{"method":"POST","url":"https://api.example.test/graphql","headers":[{"name":"Content-Type","value":"application/json"}],"postData":{"text":"{\"query\":\"query Viewer { viewer { id } }\"}"}},
                "response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"text":"{\"data\":{}}"}}
            }]}}),encoding="utf-8")
            out=root/"out"
            result=analyze_traffic(har,kind="har",out_dir=out,db_path=root/"research.db")
            self.assertEqual(result["schema_version"],"2.3")
            self.assertIn("correlations",result)
            self.assertEqual(result["correlations"]["correlation_count"],0)
            artifact=out/"correlations.json"
            self.assertTrue(artifact.exists())
            saved=json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(saved,result["correlations"])


if __name__=="__main__":
    unittest.main()
