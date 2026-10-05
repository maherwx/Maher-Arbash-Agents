import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from maher_bounty.zap_cli import run_zap_baseline
from maher_bounty.agent_tool_router import run_agent_tool_requests


class ZapCliTests(unittest.TestCase):
    def test_agent_zap_aliases_use_shared_native_adapter(self):
        url = "https://app.example.test/"
        for alias in ["zap", "zaproxy", "zap.sh", "zap-baseline.py"]:
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as td, \
                    patch("maher_bounty.agent_tool_router.run_zap_baseline", return_value={"tool": "zap-baseline.py", "status": "missing"}) as adapter:
                result = run_agent_tool_requests([{"agent": "fixture", "tool_requests": [{"tool": alias, "targets": [url]}]}],
                                                 [url], td, scope={"assets": [url]})
                self.assertEqual(adapter.call_args.args[0], url)
                self.assertEqual(len(result["runs"]), 1)

    def test_native_cli_generates_exact_url_plan_and_checks_report(self):
        target = "https://app.example.test/path?q=a&b=two"
        for executable in ["zaproxy", "zap.sh"]:
            with self.subTest(executable=executable), tempfile.TemporaryDirectory() as td:
                def execute(command, timeout):
                    self.assertEqual(command[0], executable)
                    self.assertEqual(timeout, 180)
                    self.assertIn("api.disable=true", command)
                    plan = yaml.safe_load(Path(command[-1]).read_text())
                    self.assertEqual([job["type"] for job in plan["jobs"]], ["requestor", "passiveScan-wait", "report"])
                    self.assertEqual(plan["jobs"][0]["requests"], [{"url": target, "method": "GET"}])
                    self.assertEqual(plan["env"]["contexts"][0]["includePaths"], ["^" + re.escape(target) + "$"])
                    root = Path(plan["jobs"][-1]["parameters"]["reportDir"])
                    (root / "report.json").write_text(json.dumps({"site": []}))
                    return {"status": "ok", "returncode": 0, "command": command}
                with patch("maher_bounty.zap_cli.shutil.which", side_effect=lambda name: name if name == executable else None):
                    result = run_zap_baseline(target, td, {"assets": ["app.example.test"]}, execute)
                self.assertEqual(result["report_status"], "available")
                self.assertEqual(result["coverage"], "exact_url_passive")

    def test_missing_or_invalid_report_does_not_claim_success(self):
        for document in [None, "not json", "[]", '{"site":{}}']:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as td:
                def execute(command, timeout):
                    if document is not None:
                        (Path(command[-1]).parent / "report.json").write_text(document)
                    return {"status": "ok", "returncode": 0}
                with patch("maher_bounty.zap_cli.shutil.which", side_effect=lambda name: name if name == "zaproxy" else None):
                    result = run_zap_baseline("https://app.example.test/", td, {"assets": ["app.example.test"]}, execute)
                self.assertEqual(result["status"], "nonzero")
                self.assertNotIn("report_status", result)

    def test_scope_credentials_and_variable_expansion_rejected_before_launch(self):
        for url in ["https://outside.test/", "https://user:secret@app.example.test/", "https://app.example.test/#fragment", "https://app.example.test/${env}"]:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as td:
                execute = Mock()
                with self.assertRaises(ValueError):
                    run_zap_baseline(url, td, {"assets": ["app.example.test"]}, execute)
                execute.assert_not_called()
                self.assertFalse(list(Path(td).iterdir()))

    def test_packaged_precedence_missing_binary_and_timeout_diagnostics(self):
        with tempfile.TemporaryDirectory() as td:
            execute = Mock(return_value={"status": "timeout"})
            with patch("maher_bounty.zap_cli.shutil.which", return_value="installed"):
                result = run_zap_baseline("https://app.example.test/", td, {"assets": ["app.example.test"]}, execute)
            self.assertEqual(execute.call_args.args[0][0], "zap-baseline.py")
            self.assertEqual(result["status"], "timeout")
            execute.reset_mock()
            with patch("maher_bounty.zap_cli.shutil.which", return_value=None):
                result = run_zap_baseline("https://app.example.test/", td, {"assets": ["app.example.test"]}, execute)
            self.assertEqual(result["status"], "missing")
            execute.assert_not_called()
