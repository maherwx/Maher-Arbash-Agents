import tempfile
import unittest
from pathlib import Path

from maher_bounty.advanced_analysis import (
    build_application_intelligence,
    normalize_evidence,
    validate_evidence,
    build_agent_workstreams,
    write_advanced_artifacts,
)


class AdvancedAnalysisTests(unittest.TestCase):
    def test_application_intelligence_classifies_research_queues(self):
        inventory={
            "endpoints":[
                {"value":"https://example.test/api/v1/users?id=1"},
                {"value":"https://example.test/assets/app.js"},
                {"value":"https://example.test/login"},
                {"value":"https://example.test/upload"},
            ]
        }
        data=build_application_intelligence("https://example.test",inventory)
        self.assertEqual(data["endpoint_count"],4)
        self.assertEqual(len(data["api_candidates"]),1)
        self.assertEqual(len(data["javascript_assets"]),1)
        self.assertEqual(len(data["auth_state_candidates"]),1)
        self.assertEqual(len(data["upload_candidates"]),1)
        self.assertIn("id",data["identifier_parameters"])

    def test_validation_promotes_evidence_backed_finding(self):
        active={
            "target":"https://example.test",
            "findings":[
                {
                    "source":"nuclei",
                    "sources":["nuclei","independent-validator"],
                    "title":"Security misconfiguration",
                    "severity":"high",
                    "target":"https://example.test/a",
                    "evidence":"observable response condition",
                    "validated":True,
                }
            ],
        }
        normalized=normalize_evidence(active)
        result=validate_evidence(normalized)
        self.assertEqual(result["counts"]["evidence_backed"],1)
        self.assertEqual(result["evidence_backed"][0]["validation_state"],"evidence-backed")
        self.assertGreaterEqual(result["evidence_backed"][0]["validation_score"],0.7)

    def test_weak_signal_is_not_confirmed(self):
        active={"findings":[{"source":"tool","title":"Weak signal","severity":"info","target":"x","validated":False}]}
        result=validate_evidence(normalize_evidence(active))
        self.assertEqual(result["counts"]["evidence_backed"],0)
        self.assertEqual(result["counts"]["rejected"],1)

    def test_artifacts_are_written(self):
        intelligence=build_application_intelligence("https://example.test",{"endpoints":[]})
        validation=validate_evidence([])
        workstreams=build_agent_workstreams(intelligence,validation)
        with tempfile.TemporaryDirectory() as td:
            write_advanced_artifacts(td,intelligence,validation,workstreams)
            self.assertTrue((Path(td)/"application-intelligence.json").is_file())
            self.assertTrue((Path(td)/"validated-evidence.json").is_file())
            self.assertTrue((Path(td)/"agent-workstreams.json").is_file())


if __name__=="__main__":
    unittest.main()
