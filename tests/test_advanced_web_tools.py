import json
import unittest

from maher_bounty.advanced_web_tools import run_advanced_web_tools


def har_message(headers, body="", status=None):
    payload = {"headers": [{"name": name, "value": value} for name, value in headers.items()]}
    if status is None:
        payload["postData"] = {"text": body}
    else:
        payload["status"] = status
        payload["content"] = {"text": body}
    return json.dumps(payload)


class AdvancedWebToolsTests(unittest.TestCase):
    def test_five_tools_extract_deep_signals_without_persisting_secrets_or_bodies(self):
        records = [
            {
                "source": "har", "url": "https://api.example.test/api/items/42?sort=asc&token=secret-query",
                "method": "GET", "status": 403, "sequence": 1, "identity": "actor-secret",
                "request_raw": har_message({"Accept": "application/json"}),
                "response_raw": har_message({"Content-Type": "application/json"}, '{"error":"private-message"}', 403),
            },
            {
                "source": "burp", "url": "https://api.example.test/api/items/42?sort=desc&token=other-secret",
                "method": "GET", "status": 200, "sequence": 2, "identity": "actor-secret",
                "request_raw": har_message({"Cookie": "session=credential-secret", "Accept": "application/json"}),
                "response_raw": har_message({
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                    "Set-Cookie": "sid=private-cookie; HttpOnly; SameSite=None",
                }, '{"id":42,"name":"private-response"}', 200),
            },
        ]

        result = run_advanced_web_tools(records)
        self.assertEqual(set(result), {
            "request_surface", "auth_boundary", "identity_differential",
            "response_posture", "parameter_behavior", "workflow_transitions",
        })
        self.assertGreaterEqual(result["request_surface"]["route_family_count"], 1)
        params = result["request_surface"]["routes"][0]["parameter_names"]
        self.assertIn("sort", params)
        self.assertNotIn("token", params)
        self.assertEqual(result["auth_boundary"]["candidate_count"], 1)
        self.assertGreaterEqual(result["parameter_behavior"]["signal_count"], 1)
        posture = result["response_posture"]["hosts"][0]["signals"]
        self.assertIn("wildcard_cors_with_credentials", posture)
        self.assertIn("samesite_none_without_secure", posture)
        self.assertGreaterEqual(result["workflow_transitions"]["transition_count"], 1)

        serialized = json.dumps(result)
        for secret in ("secret-query", "other-secret", "credential-secret", "actor-secret", "private-message", "private-cookie", "private-response"):
            self.assertNotIn(secret, serialized)

    def test_multi_identity_same_resource_is_a_review_candidate_without_leaking_identity(self):
        records = [
            {
                "url": "https://api.example.test/api/orders/42?token=secret-a",
                "method": "GET", "status": 200, "identity": "account-a-session-secret",
                "request_raw": har_message({"Cookie": "session=account-a-session-secret"}),
                "response_raw": har_message({"Content-Type": "application/json"}, '{"order":"private-a"}', 200),
            },
            {
                "url": "https://api.example.test/api/orders/42?token=secret-b",
                "method": "GET", "status": 200, "identity": "account-b-session-secret",
                "request_raw": har_message({"Cookie": "session=account-b-session-secret"}),
                "response_raw": har_message({"Content-Type": "application/json"}, '{"order":"private-b"}', 200),
            },
        ]
        result = run_advanced_web_tools(records)["identity_differential"]
        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["classification"], "shared_success_requires_authorization_review")
        self.assertEqual(candidate["status"], "manual_review")
        serialized = json.dumps(result)
        for secret in ("account-a-session-secret", "account-b-session-secret", "private-a", "private-b", "secret-a", "secret-b"):
            self.assertNotIn(secret, serialized)

    def test_identity_differential_needs_two_distinct_captured_actors(self):
        records = [{
            "url": "https://api.example.test/api/orders/42",
            "method": "GET", "status": 200, "identity": "one-session",
            "request_raw": "",
            "response_raw": har_message({"Content-Type": "application/json"}, '{"order":42}', 200),
        }]
        result = run_advanced_web_tools(records)["identity_differential"]
        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["comparison_count"], 0)
    def test_surface_routes_hide_url_credentials_and_opaque_path_tokens(self):
        record = {
            "url": "https://user:password@example.test/reset/token/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/42",
            "method": "GET", "source": "burp", "status": 200,
            "request_raw": "", "response_raw": "",
        }
        result = run_advanced_web_tools([record])
        serialized = json.dumps(result)
        self.assertNotIn("user:password", serialized)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", serialized)
        self.assertIn("example.test", serialized)


if __name__ == "__main__":
    unittest.main()
