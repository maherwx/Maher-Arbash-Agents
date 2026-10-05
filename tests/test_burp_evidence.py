import unittest

from maher_bounty.burp_evidence import build_scoped_traffic_evidence


class BurpEvidenceTests(unittest.TestCase):
    def test_evidence_is_scope_filtered_and_redacts_sensitive_values(self):
        route = "https://app.example.test/api/items?id=7"
        records = [
            {
                "source": "burp", "url": route, "method": "POST", "status": 200,
                "request_raw": "POST /api/items?id=7 HTTP/1.1\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\nContent-Type: application/json\r\n\r\n{\"x\":1}",
                "response_raw": "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
            },
            {
                "source": "burp", "url": "https://out.example/path", "method": "GET",
                "request_raw": "", "response_raw": "",
            },
        ]
        result = build_scoped_traffic_evidence(
            records, {"assets": ["https://app.example.test"], "out_of_scope": []}
        )
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["out_of_scope_records_filtered"], 1)
        row = result["records"][0]
        self.assertEqual(row["url"], route)
        self.assertEqual(row["query_parameter_names"], ["id"])
        self.assertIn("content-type", row["request_header_names"])
        self.assertNotIn("authorization", row["request_header_names"])
        self.assertNotIn("cookie", row["request_header_names"])
        self.assertNotIn("set-cookie", row["response_header_names"])
        self.assertNotIn("secret", str(result))

    def test_har_json_traffic_does_not_leak_header_or_body_values(self):
        import json

        record = {
            "source": "har",
            "url": "https://app.example.test/items?token=private",
            "method": "POST",
            "request_raw": json.dumps({
                "headers": [
                    {"name": "Authorization", "value": "Bearer secret"},
                    {"name": "X-Trace", "value": "trace-secret"},
                ],
                "postData": {"text": "private body"},
            }),
            "response_raw": json.dumps({
                "headers": [{"name": "Set-Cookie", "value": "sid=secret"}],
                "content": {"text": "private response"},
            }),
        }
        result = build_scoped_traffic_evidence(
            [record], {"assets": ["https://app.example.test"], "out_of_scope": []}
        )
        self.assertEqual(result["records"][0]["request_header_names"], ["x-trace"])
        self.assertNotIn("private body", str(result))
        self.assertNotIn("secret", str(result))
        self.assertTrue(result["records"][0]["request_body_present"])


if __name__ == "__main__":
    unittest.main()
