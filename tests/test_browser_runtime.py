import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from maher_bounty.workflow_execution import execute_workflows


@unittest.skipUnless(os.environ.get("MAHER_BROWSER_TESTS") == "1", "opt-in real Chromium fixture suite")
class BrowserRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                seen.append((self.path, self.headers.get("Cookie")))
                if self.path == "/external-redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://localhost:" + str(self.server.server_port) + "/credential-leak")
                    self.end_headers()
                    return
                if self.path == "/local-redirect":
                    self.send_response(302)
                    self.send_header("Location", "/check")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if self.path == "/login":
                    text = "<input name='user'><button id='login'>login</button><script>document.querySelector('#login').onclick=()=>{document.cookie='session='+document.querySelector('input').value+'; path=/'; document.body.innerHTML='<div id=ready>logged in</div><input id=csrf value=token-fixture>';}</script>"
                elif self.path.split("?")[0] == "/check":
                    text = "<div id=state>" + ("authenticated" if self.headers.get("Cookie") == "session=owner" else "anonymous") + "</div>"
                else:
                    text = "<div id=state>loading</div><script>setTimeout(()=>document.querySelector('#state').textContent='private-order-42',100)</script>"
                self.wfile.write(text.encode())
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def execute(self, config):
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [self.origin]}, td, authorized=True)
            serialized = (Path(td) / "workflow-evidence.json").read_text()
            self.assertNotIn("token-fixture", serialized)
            self.assertNotIn("session=owner", serialized)
            return result

    def test_javascript_rendered_resource_policy(self):
        config = {"engine": "browser", "identities": {name: {"origin": self.origin} for name in ["owner", "other"]},
                  "access_cases": [{"id": "private-rendered-order", "request": {"url": self.origin + "/order", "browser": {"wait_for": "#state:text-is('private-order-42')"}},
                                    "allowed": ["owner"], "denied": ["other"], "proof": {"contains": ["private-order-42"]}}]}
        result = self.execute(config)
        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["validated"])
        self.assertGreaterEqual(result["transport"]["network_requests"], 4)

    def test_form_login_cookie_isolation_and_dom_capture(self):
        config = {"engine": "browser", "identities": {name: {"origin": self.origin} for name in ["owner", "other"]},
                  "workflows": [
                      {"id": "login-and-check", "identity": "owner", "steps": [
                          {"request": {"url": self.origin + "/login", "browser": {
                              "actions": [{"kind": "fill", "selector": "input[name=user]", "value": "owner"}, {"kind": "click", "selector": "#login"}],
                              "wait_for": "#ready", "capture_dom": {"csrf": {"selector": "#csrf", "attribute": "value"}}}},
                           "expect": {"contains": ["logged in"]}},
                          {"request": {"url": self.origin + "/check?csrf={{csrf}}"}, "expect": {"contains": ["authenticated"]}}]},
                      {"id": "isolated-other", "identity": "other", "steps": [
                          {"request": {"url": self.origin + "/check"}, "expect": {"contains": ["anonymous"]}}]}]}
        result = self.execute(config)
        self.assertFalse(result["findings"])
        self.assertTrue(all(d["status"] == "completed" for d in result["decisions"]))
        checks = [(path, cookie) for path, cookie in self.seen if path.startswith("/check")]
        self.assertEqual(checks[0][1], "session=owner")
        self.assertIsNone(checks[-1][1])

    def test_outside_origin_redirect_never_contacts_destination(self):
        config = {"engine": "browser", "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "redirect-control", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/external-redirect"}, "expect": {"statuses": [200]}}]}]}
        result = self.execute(config)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(any(path == "/credential-leak" for path, _ in self.seen))
        self.assertGreater(result["transport"]["blocked_requests"], 0)

    def test_same_origin_redirect_is_allowed(self):
        config = {"engine": "browser", "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "redirect-control", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/local-redirect"}, "expect": {"contains": ["anonymous"]}}]}]}
        result = self.execute(config)
        self.assertFalse(result["findings"])
        self.assertEqual(result["status"], "completed")
