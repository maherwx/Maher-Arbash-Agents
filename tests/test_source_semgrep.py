import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from maher_bounty import source_semgrep


class SemgrepTaintRuleTests(unittest.TestCase):
    def test_local_js_rule_tracks_configured_request_sources_to_sinks(self):
        snapshots = {"routes.js": b"const value = req.query.name; eval(value);"}
        files = [{"path": "routes.js", "language": "javascript", "sha256": "a" * 64}]
        observed = {}

        def fake_run(command, **kwargs):
            rules_path = Path(command[command.index("--config") + 1])
            source_root = Path(command[-1])
            generated = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
            observed["taint_rule"] = next(rule for rule in generated
                if rule["id"] == "maher-javascript-source-to-sink-flow")
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "errors": [],
                "paths": {"scanned": [str(source_root / "routes.js")]},
                "results": [{"check_id": "maher-javascript-source-to-sink-flow",
                             "path": str(source_root / "routes.js"), "start": {"line": 1}}],
            }))

        with patch.object(source_semgrep.shutil, "which", return_value="/local/semgrep"), \
                patch.object(source_semgrep, "run", side_effect=fake_run):
            metadata, findings = source_semgrep._review_semgrep(snapshots, files)

        self.assertEqual(observed["taint_rule"]["mode"], "taint")
        self.assertIn({"pattern": "$REQ.query"}, observed["taint_rule"]["pattern-sources"])
        self.assertEqual(metadata["taint_rule_languages"], ["javascript"])
        self.assertEqual(findings[0]["confidence"], "intrafile_taint_candidate")
        self.assertFalse(findings[0]["validated"])


if __name__ == "__main__":
    unittest.main()
