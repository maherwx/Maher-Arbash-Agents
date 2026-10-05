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
                "method": "GET", "status": 403, "sequence": 1, "identity": "",
                "request_raw": har_message({"Accept": "application/json"}),
                "response_raw": har_message({"Content-Type": "application/json"}, '{"error":"private-message"}', 403),
            },
            {
                "source": "burp", "url": "https://api.example.test/api/items/42?sort=desc&token=other-secret",
                "method": "GET", "status": 200, "sequence": 2, "identity": "credential-secret",
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
            "request_surface", "auth_boundary", "response_posture",
            "parameter_behavior", "workflow_transitions",
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
        for secret in ("secret-query", "other-secret", "credential-secret", "private-message", "private-cookie", "private-response"):
            self.assertNotIn(secret, serialized)


if __name__ == "__main__":
    unittest.main()
