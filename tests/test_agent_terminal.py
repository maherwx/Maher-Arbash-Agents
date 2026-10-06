import os
import tempfile
import unittest
from unittest.mock import patch

from maher_bounty.agent_terminal import run_agent_terminal, AgentExecutionInputError


def auth_manifest():
    origin = "https://app.example.test"
    return {
        "identities": {
            "owner": {"origin": origin, "headers_env": {"Cookie": "MAHER_TEST_COOKIE"}},
            "other": {"origin": origin},
        },
        "access_cases": [{"id": "private", "request": {"url": origin + "/private"},
                           "allowed": ["owner"], "denied": ["other"],
                           "proof": {"contains": ["private test record"]}}],
        "browser_xss_profile": {
            "identity": "owner",
            "session_request": {"url": origin + "/api/session"},
            "session_proof": {"contains": ["test-owner"]},
        },
    }


class AgentTerminalTests(unittest.TestCase):
    def test_authenticated_adapter_requires_a_supplied_profile(self):
        target = "https://app.example.test/search?q=record"
        packets = [{"agent": "operator", "tool_requests": [
            {"tool": "browser-xss-auth", "targets": [target]},
        ]}]
        with self.assertRaisesRegex(AgentExecutionInputError, "supplied workflow profile"):
            run_agent_terminal([target], {"assets": ["https://app.example.test"], "out_of_scope": []},
                               tempfile.gettempdir(), authorized=True, requests=packets)

    def test_profile_and_browser_prerequisite_enable_fixed_authenticated_plan(self):
        target = "https://app.example.test/search?q=record"
        snapshot = {"tools": [
            {"tool": "browser-xss", "available": True, "status": "dependency_present_browser_unverified"},
            {"tool": "browser-xss-auth", "available": False, "status": "workflow_only"},
        ]}
        with tempfile.TemporaryDirectory() as out, patch.dict(os.environ, {"MAHER_TEST_COOKIE": "local-fixture"}), \
             patch("maher_bounty.agent_terminal.tool_readiness_snapshot", return_value=snapshot):
            result = run_agent_terminal(
                [target], {"assets": ["https://app.example.test"], "out_of_scope": []}, out,
                authorized=True, workflow_manifest=auth_manifest(), plan_only=True, tool_profile="web")
        requests = [row for packet in result["plan"]["initial_requests"] for row in packet["tool_requests"]]
        self.assertIn("browser-xss-auth", {row["tool"] for row in requests})
        self.assertNotIn("local-fixture", str(result["plan"]))
        self.assertEqual(result["plan"]["tool_readiness"]["commands_launched"], False)

    def test_auth_profile_does_not_make_browser_adapter_available_when_dependency_missing(self):
        target = "https://app.example.test/search?q=record"
        snapshot = {"tools": [
            {"tool": "browser-xss", "available": False, "status": "dependency_missing"},
            {"tool": "browser-xss-auth", "available": False, "status": "workflow_only"},
        ]}
        with tempfile.TemporaryDirectory() as out, patch.dict(os.environ, {"MAHER_TEST_COOKIE": "local-fixture"}), \
             patch("maher_bounty.agent_terminal.tool_readiness_snapshot", return_value=snapshot):
            result = run_agent_terminal(
                [target], {"assets": ["https://app.example.test"], "out_of_scope": []}, out,
                authorized=True, workflow_manifest=auth_manifest(), plan_only=True, tool_profile="web")
        requests = [row for packet in result["plan"]["initial_requests"] for row in packet["tool_requests"]]
        self.assertNotIn("browser-xss-auth", {row["tool"] for row in requests})

