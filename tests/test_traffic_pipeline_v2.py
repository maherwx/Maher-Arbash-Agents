import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.traffic_pipeline import analyze_traffic


class TrafficPipelineV2Tests(unittest.TestCase):
    def test_integrated_pipeline_emits_advanced_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            har = {
                "log": {"entries": [{
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.test/graphql",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"text": '{"query":"query Viewer { viewer { id } }"}'},
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"data":{"viewer":{"id":"1"}}}'},
                    },
                }]}
            }
            source = root / "sample.har"
            source.write_text(json.dumps(har), encoding="utf-8")
            out = root / "out"
            result = analyze_traffic(source, kind="har", out_dir=out, db_path=root / "research.db")
            self.assertEqual(result["schema_version"], "2.2")
            self.assertIn("protocols", result)
            self.assertIn("workflow", result)
            self.assertIn("test_matrix", result)
            self.assertIn("priorities", result)
            self.assertIn("knowledge_graph", result)
            self.assertIn("provenance", result)
            self.assertIn("evidence_report", result)
            self.assertGreaterEqual(result["priorities"]["target_count"], 1)
            self.assertGreaterEqual(result["knowledge_graph"]["stats"]["nodes"], 2)
            for name in (
                "canonical-http.json", "behavior-model.json", "anomalies.json",
                "protocol-intelligence.json", "workflow-model.json",
                "workflow-divergences.json", "test-matrix.json", "priorities.json",
                "knowledge-graph.json", "provenance-chains.json",
                "provenance-summary.json", "evidence-report.json", "summary.json",
            ):
                self.assertTrue((out / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
