import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from maher_bounty.workflow_execution import execute_workflows, Transport


def config(proof):
    origin = "https://app.example.test"
    return {"identities": {name: {"origin": origin} for name in ("owner", "other")},
            "access_cases": [{"id": "order", "allowed": ["owner"], "denied": ["other"],
                              "request": {"url": origin + "/orders/42"}, "proof": proof}]}


class AccessProofValidationTests(unittest.TestCase):
    def test_malformed_or_tautological_proof_fails_before_network(self):
        proofs = [{"contains": [""]}, {"contains": ["   "]}, {"contains": "order"},
                  {"json_equals": []}, {"json_equals": {"owner": "owner"}},
                  {"contains": ["order"], "statuses": ["200"]},
                  {"contains": ["order"], "statuses": [True]},
                  {"contains": ["order"], "statuses": [999]},
                  {"contains": ["order"], "contain": ["ignored"]}]
        sender = Mock()
        with tempfile.TemporaryDirectory() as td:
            for proof in proofs:
                with self.subTest(proof=proof), self.assertRaises(ValueError):
                    execute_workflows(config(proof), {"assets": ["app.example.test"]}, td,
                                      authorized=True, transport=sender)
        sender.assert_not_called()

    def test_workflow_with_unknown_or_empty_assertions_fails_before_network(self):
        sender = Mock()
        with tempfile.TemporaryDirectory() as td:
            for expected in [{"contains": []}, {"status": 200}, {"statuses": []}, {"absent": "error"}]:
                manifest = config({"contains": ["order"]})
                manifest["access_cases"] = []
                manifest["workflows"] = [{"id": "test", "identity": "owner", "steps": [
                    {"request": {"url": "https://app.example.test/"}, "expect": expected}]}]
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    execute_workflows(manifest, {"assets": ["app.example.test"]}, td,
                                      authorized=True, transport=sender)
        sender.assert_not_called()

    def test_direct_transport_checks_origin_and_credential_overrides(self):
        sender = Transport({"owner": {"origin": "https://app.example.test"}})
        for request in [{"url": "https://outside.test/"}, {"url": "http://app.example.test/"},
                        {"url": "https://user:secret@app.example.test/"},
                        {"url": "https://app.example.test/", "headers": {"Cookie": "override"}}]:
            with self.subTest(request=request), self.assertRaises(ValueError):
                sender("owner", request)
        self.assertEqual(sender.count, 0)

    def test_empty_captured_marker_cannot_become_a_workflow_success(self):
        manifest = config({"contains": ["order"]})
        manifest["access_cases"] = []
        manifest["workflows"] = [{"id": "dynamic-proof", "identity": "owner", "steps": [
            {"request": {"url": "https://app.example.test/first"}, "expect": {"statuses": [200]}, "capture": {"marker": "/marker"}},
            {"request": {"url": "https://app.example.test/second"}, "expect": {"contains": ["{{marker}}"]}}]}]
        sender = Mock(spec=[], return_value={"status": 200, "body": '{"marker":""}', "headers": {}})
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(manifest, {"assets": ["app.example.test"]}, td, authorized=True, transport=sender)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["requests"], 1)
        self.assertFalse(result["findings"])


class HttpCookieRotationTests(unittest.TestCase):
    def test_supplied_cookie_rotates_and_stays_isolated_with_redacted_evidence(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                seen.append(self.headers.get("Cookie"))
                self.send_response(200)
                if self.path == "/rotate":
                    self.send_header("Set-Cookie", "session=rotated-secret; Path=/")
                self.end_headers()
                state = "authenticated" if self.headers.get("Cookie") in {"session=seed-secret", "session=rotated-secret"} else "anonymous"
                self.wfile.write(json.dumps({"state": state}).encode())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        manifest = {"identities": {"owner": {"origin": origin, "headers_env": {"Cookie": "MAHER_HTTP_COOKIE"}},
                                   "other": {"origin": origin}},
                    "workflows": [{"id": "rotate", "identity": "owner", "steps": [
                        {"request": {"url": origin + "/rotate"}, "expect": {"json_equals": {"/state": "authenticated"}}},
                        {"request": {"url": origin + "/check"}, "expect": {"json_equals": {"/state": "authenticated"}}}]},
                        {"id": "isolated", "identity": "other", "steps": [
                        {"request": {"url": origin + "/check"}, "expect": {"json_equals": {"/state": "anonymous"}}}]}]}
        try:
            with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"MAHER_HTTP_COOKIE": "session=seed-secret"}):
                result = execute_workflows(manifest, {"assets": [origin]}, td, authorized=True)
                evidence = (Path(td) / "workflow-evidence.json").read_text()
                self.assertEqual(result["status"], "completed")
                self.assertFalse(result["findings"])
                self.assertNotIn("seed-secret", evidence)
                self.assertNotIn("rotated-secret", evidence)
            self.assertEqual(seen, ["session=seed-secret", "session=rotated-secret", None])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
