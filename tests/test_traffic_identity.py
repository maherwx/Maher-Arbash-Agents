import json
import tempfile
import unittest
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from maher_bounty.traffic_ingest import load_burp_xml, load_har


class TrafficIdentityTests(unittest.TestCase):
    def test_burp_xml_extracts_hashed_session_identity(self):
        root = Element("items")
        for index, session in enumerate(("account-a-secret", "account-a-secret", "account-b-secret")):
            item = SubElement(root, "item")
            SubElement(item, "url").text = "https://app.example.test/orders/42"
            SubElement(item, "method").text = "GET"
            SubElement(item, "status").text = "200"
            request = SubElement(item, "request")
            request.text = f"GET /orders/42 HTTP/1.1\r\nHost: app.example.test\r\nCookie: JSESSIONID={session}\r\n\r\n"
            SubElement(item, "response").text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "burp.xml"
            path.write_bytes(tostring(root))
            records = load_burp_xml(path)
        identities = [record["identity"] for record in records]
        self.assertEqual(identities[0], identities[1])
        self.assertNotEqual(identities[0], identities[2])
        self.assertTrue(all(identity.startswith("actor-") for identity in identities))
        self.assertNotIn("account-a-secret", identities[0])
        self.assertNotIn("account-b-secret", identities[2])

    def test_har_supports_common_session_cookie_names_without_persisting_values(self):
        entries = []
        for session in ("session-a-secret", "session-b-secret"):
            entries.append({
                "request": {
                    "url": "https://app.example.test/orders/42",
                    "method": "GET",
                    "headers": [{"name": "Cookie", "value": f"theme=dark; laravel_session={session}"}],
                },
                "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
            })
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "traffic.har"
            path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")
            records = load_har(path)
        self.assertNotEqual(records[0]["identity"], records[1]["identity"])
        self.assertNotIn("session-a-secret", records[0]["identity"])
        self.assertNotIn("session-b-secret", records[1]["identity"])


if __name__ == "__main__":
    unittest.main()
