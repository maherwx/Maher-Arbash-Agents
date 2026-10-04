import tempfile
import unittest
from pathlib import Path

from maher_bounty.protocol_intelligence import analyze_http_records, analyze_source_protocols


class ProtocolIntelligenceTests(unittest.TestCase):
    def test_http_protocol_detection(self):
        records = [
            {"url": "https://api.example.test/graphql", "request_raw": "POST /graphql HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"query\":\"query Viewer { viewer { id } }\"}", "response_raw": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"},
            {"url": "https://api.example.test/pkg.Service/Method", "request_raw": "POST /pkg.Service/Method HTTP/2\r\nContent-Type: application/grpc\r\n\r\n", "response_raw": "HTTP/2 200\r\ngrpc-status: 0\r\n\r\n"},
            {"url": "wss://stream.example.test/events", "request_raw": "GET /events HTTP/1.1\r\nUpgrade: websocket\r\n\r\n", "response_raw": ""},
        ]
        result = analyze_http_records(records)
        self.assertGreaterEqual(result["protocol_counts"].get("graphql", 0), 1)
        self.assertGreaterEqual(result["protocol_counts"].get("grpc", 0), 1)
        self.assertGreaterEqual(result["protocol_counts"].get("websocket", 0), 1)

    def test_source_protocol_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "service.proto").write_text('syntax="proto3"; service Accounts { rpc Get (Req) returns (Resp); }', encoding="utf-8")
            (root / "client.ts").write_text('const socket = new WebSocket("wss://example.test/events"); const q=`mutation UpdateUser { updateUser { id } }`;', encoding="utf-8")
            (root / "openapi.yaml").write_text(
                "openapi: 3.1.0\n"
                "info:\n"
                "  title: Example\n"
                "  version: 1.0.0\n"
                "paths:\n"
                "  /health:\n"
                "    get:\n"
                "      responses:\n"
                "        '200':\n"
                "          description: ok\n",
                encoding="utf-8",
            )
            result = analyze_source_protocols(root)
            counts = result["protocol_counts"]
            self.assertIn("grpc-proto", counts)
            self.assertIn("graphql-source", counts)
            self.assertIn("websocket-source", counts)
            self.assertIn("openapi-source", counts)


if __name__ == "__main__":
    unittest.main()
