import tempfile
import unittest
from unittest.mock import Mock

from maher_bounty.workflow_execution import execute_workflows, validate_manifest


def plan(settings, engine="browser"):
    origin = "https://app.example.test"
    return {"engine": engine, "identities": {"owner": {"origin": origin}},
            "workflows": [{"id": "state", "identity": "owner", "steps": [
                {"request": {"url": origin + "/first", "browser": {"actions": [{"kind": "click", "selector": "#commit"}]}}, "expect": {"statuses": [200]}},
                {"request": {"url": origin + "/second", "browser": settings}, "expect": {"statuses": [200]}}]}]}


class BrowserPreflightTests(unittest.TestCase):
    def test_invalid_later_plan_prevents_all_earlier_requests_and_mutations(self):
        invalid = [None, [], {"action": []}, {"actions": {}},
                   {"actions": [None]}, {"actions": [{"kind": "submit", "selector": "#form"}]},
                   {"actions": [{"kind": "click", "selector": ""}]},
                   {"actions": [{"kind": "fill", "selector": "#user"}]},
                   {"actions": [{"kind": "fill", "selector": "#user", "value": "x", "value_env": "USER"}]},
                   {"actions": [{"kind": "fill", "selector": "#user", "value_env": 42}]},
                   {"actions": [{"kind": "select", "selector": "#state"}]},
                   {"actions": [{"kind": "click", "selector": "#form", "value": "x"}]},
                   {"wait_for": ""}, {"body_selector": 42}, {"wait_for_network_idle": "true"},
                   {"capture_dom": []}, {"capture_dom": {"bad-name": {"selector": "#token"}}},
                   {"capture_dom": {"token": {"selector": "#token", "attribute": ""}}},
                   {"capture_dom": {"token": {"selector": "#token", "attribut": "value"}}}]
        for settings in invalid:
            with self.subTest(settings=settings), tempfile.TemporaryDirectory() as td:
                sender = Mock()
                with self.assertRaises(ValueError):
                    execute_workflows(plan(settings), {"assets": ["app.example.test"]}, td, authorized=True, transport=sender)
                sender.assert_not_called()

    def test_unknown_engine_or_silently_ignored_browser_plan_rejected(self):
        for engine in ["chromium", "HTTP", None, "http"]:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                validate_manifest(plan({"wait_for": "#done"}, engine), {"assets": ["app.example.test"]})

    def test_supported_plan_preserves_empty_fill_and_typed_select_values(self):
        settings = {"actions": [{"kind": "fill", "selector": "#user", "value": ""},
                                {"kind": "fill", "selector": "#password", "value_env": "FIXTURE_PASSWORD"},
                                {"kind": "select", "selector": "#count", "value": 0},
                                {"kind": "check", "selector": "#agree"}],
                    "wait_for": "#done", "wait_for_network_idle": False,
                    "capture_dom": {"csrf": {"selector": "#csrf", "attribute": "value"}}, "body_selector": "main"}
        config = plan(settings)
        self.assertIs(validate_manifest(config, {"assets": ["app.example.test"]}), config)
