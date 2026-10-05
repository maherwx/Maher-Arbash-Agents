import copy
import tempfile
import unittest
from unittest.mock import Mock, patch

from maher_bounty.workflow_execution import execute_workflows, validate_manifest


def manifest():
    return {"identities": {"owner": {"origin": "https://example.test"}}, "workflows": [
        {"id": "lifecycle", "identity": "owner", "steps": [
            {"request": {"url": "https://example.test/create", "method": "POST"}, "expect": {"statuses": [201]}, "capture": {"id": "/id"}},
            {"request": {"url": "https://example.test/objects/{{id}}"}, "expect": {"json_equals": {"/id": "{{id}}"}}}]}]}


class WorkflowVariablePreflightTests(unittest.TestCase):
    def test_later_missing_variables_prevent_earlier_mutation_and_session_reset(self):
        for location in ["url", "body", "header", "expect"]:
            config = manifest()
            step = config["workflows"][0]["steps"][1]
            if location == "url":
                step["request"]["url"] += "?token={{missing}}"
            elif location == "body":
                step["request"].update(method="POST", body={"items": ["{{missing}}"]})
            elif location == "header":
                step["request"]["headers"] = {"X-Context": "prefix-{{missing}}"}
            else:
                step["expect"] = {"contains": ["{{missing}}"]}
            sender = Mock(spec=["reset"])
            with self.subTest(location=location), tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
                execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True, transport=sender)
            sender.assert_not_called()
            sender.reset.assert_not_called()

    def test_current_or_other_workflow_capture_cannot_satisfy_reference(self):
        config = manifest()
        config["workflows"][0]["steps"][0]["expect"] = {"json_equals": {"/id": "{{id}}"}}
        with self.assertRaises(ValueError):
            validate_manifest(config, {"assets": ["example.test"]})
        config = manifest()
        second = copy.deepcopy(config["workflows"][0])
        second.update(id="other", steps=second["steps"][1:])
        config["workflows"].append(second)
        with self.assertRaises(ValueError):
            validate_manifest(config, {"assets": ["example.test"]})

    def test_initial_typed_values_and_prior_captures_are_supported(self):
        config = manifest()
        config["workflows"][0]["variables"] = {"initial": 42}
        config["workflows"][0]["steps"][0]["request"]["body"] = {"parent": "{{initial}}"}
        sender = Mock(spec=[], side_effect=[{"status": 201, "body": '{"id":7}'}, {"status": 200, "body": '{"id":7}'}])
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True, transport=sender)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(sender.call_args_list[0].args[1]["body"]["parent"], 42)
        self.assertEqual(sender.call_args_list[1].args[1]["url"], "https://example.test/objects/7")

    def test_dom_capture_dependencies_and_ambiguous_capture_sources(self):
        config = manifest()
        config["engine"] = "browser"
        first = config["workflows"][0]["steps"][0]
        first["request"].pop("method")
        first["request"]["browser"] = {"capture_dom": {"id": {"selector": "#object-id"}}}
        first.pop("capture")
        validate_manifest(config, {"assets": ["example.test"]})
        first["capture"] = {"id": "/id"}
        with self.assertRaises(ValueError):
            validate_manifest(config, {"assets": ["example.test"]})

    def test_bad_initial_variable_container_or_names_fail_before_browser(self):
        for initial in [None, [], {"bad-name": 1}, {2: 1}]:
            config = manifest()
            config["engine"] = "browser"
            config["workflows"][0]["variables"] = initial
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as td, patch("maher_bounty.browser_runtime.BrowserTransport") as browser, self.assertRaises(ValueError):
                execute_workflows(config, {"assets": ["example.test"]}, td, authorized=True)
            browser.assert_not_called()
        for value in [None, [], "invalid"]:
            with self.assertRaises(ValueError):
                validate_manifest(value, {"assets": ["example.test"]})
