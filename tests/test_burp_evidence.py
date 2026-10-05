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


if __name__ == "__main__":
    unittest.main()
