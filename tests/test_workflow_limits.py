import tempfile
import time
import unittest
from unittest.mock import patch

from maher_bounty.workflow_execution import execute_workflows, Transport, validate_manifest, _wait_for_interval


class WorkflowLimitTests(unittest.TestCase):
    def config(self):
        return {"engine": "browser", "identities": {"owner": {"origin": "https://example.test"}},
                "workflows": [{"id": "read", "identity": "owner", "steps": [
                    {"request": {"url": "https://example.test/"}, "expect": {"statuses": [200]}}]}]}

    def test_invalid_limits_rejected_before_browser_launch(self):
        bad = [None, [], {"typo": 1}, {"max_requests": True}, {"max_requests": 1.5}, {"max_requests": 0}]
        for key in ["interval_seconds", "timeout_seconds", "total_seconds"]:
            bad += [{key: value} for value in [True, "10", None, -1, float("nan"), float("inf"), 10 ** 1000]]
        bad += [{"timeout_seconds": 0}, {"total_seconds": 0}]
        for limits in bad:
            config = self.config()
            config["limits"] = limits
            with self.subTest(limits=limits), tempfile.TemporaryDirectory() as td, patch("maher_bounty.browser_runtime.BrowserTransport") as browser:
                with self.assertRaises(ValueError):
                    execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True)
                browser.assert_not_called()

    def test_interval_cannot_sleep_past_remaining_budget_or_open_connection(self):
        sender = Transport({"owner": {"origin": "https://example.test"}}, interval=10, deadline=time.monotonic() + 1)
        sender.last = time.monotonic()
        with patch("maher_bounty.workflow_execution.time.sleep") as sleep, patch.object(sender.openers["owner"], "open") as opened:
            with self.assertRaises(RuntimeError):
                sender("owner", {"url": "https://example.test/"})
            sleep.assert_not_called()
            opened.assert_not_called()
            self.assertEqual(sender.count, 0)

    def test_valid_limits_and_available_pacing_budget(self):
        config = self.config()
        config["limits"] = {"max_requests": 2, "timeout_seconds": 0.5, "total_seconds": 10, "interval_seconds": 0}
        validate_manifest(config, {"assets": ["example.test"]})
        with patch("maher_bounty.workflow_execution.time.monotonic", return_value=10), patch("maher_bounty.workflow_execution.time.sleep") as sleep:
            _wait_for_interval(9.9, 0.2, 11)
            self.assertAlmostEqual(sleep.call_args.args[0], 0.1)
