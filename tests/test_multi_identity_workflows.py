import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from maher_bounty.workflow_execution import execute_workflows


def manifest(origin):
    return {"identities": {"owner": {"origin": origin, "headers_env": {"Cookie": "MAHER_STATE_OWNER"}},
                           "other": {"origin": origin}},
            "workflows": [{"id": "resource-lifecycle", "identity": "owner", "steps": [
                {"request": {"url": origin + "/create"}, "expect": {"statuses": [200]}, "capture": {"id": "/id"}},
                {"identity": "other", "request": {"url": origin + "/objects/{{id}}"}, "expect": {"statuses": [403]}},
                {"request": {"url": origin + "/objects/{{id}}"},
                 "expect": {"statuses": [200], "json_equals": {"/state": "private", "/id": "{{id}}"}}}]}]}


class MultiIdentityWorkflowTests(unittest.TestCase):
    def test_unknown_step_identity_rejected_before_requests(self):
        config = manifest("https://app.example.test")
        config["workflows"][0]["steps"][1]["identity"] = "invented"
        sender = Mock(spec=[])
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            execute_workflows(config, {"assets": ["app.example.test"]}, td, authorized=True, transport=sender)
        sender.assert_not_called()

    def test_step_origin_validated_against_selected_identity(self):
        config = manifest("https://app.example.test")
        config["identities"]["other"]["origin"] = "https://other.example.test"
        sender = Mock(spec=[])
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            execute_workflows(config, {"assets": ["app.example.test", "other.example.test"]}, td,
                              authorized=True, transport=sender)
        sender.assert_not_called()

    def test_reset_failure_is_inconclusive_without_traffic(self):
        sender = Mock(spec=["reset"])
        sender.reset.side_effect = RuntimeError("secret credential details")
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(manifest("https://app.example.test"), {"assets": ["app.example.test"]},
                                       td, authorized=True, transport=sender)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["requests"], 0)
        self.assertNotIn("secret", json.dumps(result))

    def test_denial_failure_stops_before_owner_state_check(self):
        sender = Mock(spec=[], side_effect=[
            {"status": 200, "body": '{"id":"42"}'},
            {"status": 200, "body": '{"id":"42","state":"private"}'}])
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(manifest("https://app.example.test"), {"assets": ["app.example.test"]},
                                       td, authorized=True, transport=sender)
        self.assertEqual(result["requests"], 2)
        self.assertEqual(result["decisions"][0]["status"], "invariant_failed")
        self.assertFalse(result["findings"][0]["validated"])
        self.assertEqual([call.args[0] for call in sender.call_args_list], ["owner", "other"])

    def run_lifecycle(self, engine):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                cookie = self.headers.get("Cookie")
                if self.path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return
                seen.append((self.path, cookie))
                authorized = cookie == ("session=seed" if self.path == "/create" else "session=rotated")
                self.send_response(200 if authorized else 403)
                self.send_header("Content-Type", "text/plain")
                if self.path == "/create" and authorized:
                    self.send_header("Set-Cookie", "session=rotated; Path=/")
                self.end_headers()
                self.wfile.write(json.dumps({"id": "42", "state": "private"} if authorized else {"error": "denied"}).encode())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        config = manifest(origin)
        config["engine"] = engine
        try:
            with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"MAHER_STATE_OWNER": "session=seed"}):
                result = execute_workflows(config, {"assets": [origin]}, td, authorized=True)
            self.assertEqual(result["status"], "completed")
            self.assertFalse(result["findings"])
            rows = result["observations"][0]["observations"]
            self.assertEqual([r["identity"] for r in rows], ["owner", "other", "owner"])
            self.assertEqual(seen, [("/create", "session=seed"), ("/objects/42", None), ("/objects/42", "session=rotated")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_http_cross_identity_resource_lifecycle(self):
        self.run_lifecycle("http")

    @unittest.skipUnless(os.environ.get("MAHER_BROWSER_TESTS") == "1", "real Chromium opt-in")
    def test_browser_cross_identity_resource_lifecycle(self):
        self.run_lifecycle("browser")
