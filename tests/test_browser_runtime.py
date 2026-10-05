import importlib.util
import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from maher_bounty.workflow_execution import execute_workflows
from maher_bounty.browser_runtime import BrowserTransport


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
                if self.path.split("?")[0] == "/broken":
                    self.connection.close()
                    return
                if self.path == "/state-api":
                    time.sleep(0.25)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    try:
                        self.wfile.write(b'{"state":"settled-state-42"}')
                    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                        pass
                    return
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
                if self.path == "/rotate":
                    self.send_header("Set-Cookie", "session=rotated; Path=/")
                self.end_headers()
                if self.path == "/delayed-action":
                    text = "<div>ready</div><script>setTimeout(()=>document.body.insertAdjacentHTML('beforeend','<button id=late>continue</button>'),700)</script>"
                elif self.path == "/async-state":
                    text = "<div id=state>loading</div><script>fetch('/state-api').then(r=>r.json()).then(x=>document.querySelector('#state').textContent=x.state)</script>"
                elif self.path == "/polling-state":
                    text = "<div>private-order-42</div><script>let n=0;let timer=setInterval(()=>{fetch('/state-api').catch(()=>{});if(++n===5)clearInterval(timer)},100)</script>"
                elif self.path == "/continuous-polling":
                    text = "<div>private-order-42</div><script>setInterval(()=>fetch('/state-api').catch(()=>{}),100)</script>"
                elif self.path in {"/degraded", "/blocked-dependency"}:
                    dependency = "/broken?token=secret-fixture" if self.path == "/degraded" else "http://localhost:" + str(self.server.server_port) + "/outside"
                    text = "<div>private-order-42</div><script>fetch('" + dependency + "').catch(()=>{}).finally(()=>document.body.insertAdjacentHTML('beforeend','<div id=done>done</div>'))</script>"
                elif self.path == "/login":
                    text = "<input name='user'><button id='login'>login</button><script>document.querySelector('#login').onclick=()=>{document.cookie='session='+document.querySelector('input').value+'; path=/'; document.body.innerHTML='<div id=ready>logged in</div><input id=csrf value=token-fixture>';}</script>"
                elif self.path.split("?")[0] == "/check":
                    text = "<div id=state>" + ("authenticated" if self.headers.get("Cookie") in {"session=owner", "session=rotated"} else "anonymous") + "</div>"
                elif self.path == "/rotate":
                    text = "<div>rotated</div>"
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

    def test_failed_dependency_cannot_confirm_rendered_resource_proof(self):
        self.check_incomplete_dependency("/degraded", "failed_requests")

    def test_each_dom_operation_uses_remaining_run_budget(self):
        operations = [
            {"actions": [{"kind": "fill", "selector": "#missing", "value": "fixture"}]},
            {"wait_for": "#missing"},
            {"capture_dom": {"state": {"selector": "#missing"}}},
            {"body_selector": "#missing"},
        ]
        for operation in operations:
            with self.subTest(operation=operation):
                sender = BrowserTransport({"owner": {"origin": self.origin}}, {"assets": [self.origin]}, timeout=5, interval=0)
                try:
                    settings = dict(operation)
                    settings["actions"] = [{"kind": "click", "selector": "#late"}] + operation.get("actions", [])
                    sender.deadline = time.monotonic() + 1.2
                    started = time.monotonic()
                    with self.assertRaises(RuntimeError):
                        sender("owner", {"url": self.origin + "/delayed-action", "browser": settings})
                    self.assertLess(time.monotonic() - started, 1.7)
                    self.assertEqual(sender.count, 1)
                finally:
                    sender.close()

    def test_blocked_dependency_cannot_confirm_rendered_resource_proof(self):
        self.check_incomplete_dependency("/blocked-dependency", "blocked_requests")

    def check_incomplete_dependency(self, path, counter):
        config = {"engine": "browser", "identities": {name: {"origin": self.origin} for name in ["owner", "other"]},
                  "access_cases": [{"id": "degraded", "request": {"url": self.origin + path, "browser": {"wait_for": "#done"}},
                                    "allowed": ["owner"], "denied": ["other"], "proof": {"contains": ["private-order-42"]}}]}
        result = self.execute(config)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])
        self.assertTrue(result["observations"][0]["observations"][0]["network_incomplete"])
        self.assertGreater(result["transport"][counter], 0)
        self.assertNotIn("secret-fixture", json.dumps(result))

    def test_direct_headers_and_expired_budget_fail_before_network(self):
        sender = BrowserTransport({"owner": {"origin": self.origin}}, {"assets": [self.origin]})
        try:
            with self.assertRaises(ValueError):
                sender("owner", {"url": self.origin + "/check", "headers": {"Cookie": "override"}})
            sender.deadline = time.monotonic() - 1
            with self.assertRaises(RuntimeError):
                sender("owner", {"url": self.origin + "/check"})
            self.assertEqual(sender.count, 0)
            self.assertEqual(self.seen, [])
        finally:
            sender.close()

    def test_custom_identity_header_override_rejected_before_browser_network(self):
        identities = {"owner": {"origin": self.origin, "headers_env": {"X-API-Key": "FIXTURE_BROWSER_KEY"}}}
        with patch.dict(os.environ, {"FIXTURE_BROWSER_KEY": "fixture-key"}):
            sender = BrowserTransport(identities, {"assets": [self.origin]})
        try:
            for header in ["X-API-Key", "x-api-key", "X-API-KEY"]:
                with self.subTest(header=header), self.assertRaises(ValueError):
                    sender("owner", {"url": self.origin + "/check", "headers": {header: "override"}})
            self.assertEqual(sender.count, 0)
            self.assertFalse(self.seen)
            response = sender("owner", {"url": self.origin + "/check", "headers": {"Accept": "text/html"}})
            self.assertEqual(response["status"], 200)
            self.assertNotIn("fixture-key", json.dumps(sender.summary()))
        finally:
            sender.close()

    def test_network_idle_observes_async_state_before_proof(self):
        config = {"engine": "browser", "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "settle", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/async-state", "browser": {"wait_for_network_idle": True}},
                       "expect": {"contains": ["settled-state-42"]}}]}]}
        result = self.execute(config)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["findings"])
        self.assertEqual(result["observations"][0]["observations"][0]["pending_requests"], 0)

    def test_busy_network_cannot_wait_past_budget_or_confirm_stale_dom(self):
        config = {"engine": "browser", "limits": {"timeout_seconds": 1, "total_seconds": 3, "interval_seconds": 0.1},
                  "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "polling", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/polling-state", "browser": {"wait_for_network_idle": True}},
                       "expect": {"contains": ["private-order-42"]}}]}]}
        started = time.monotonic()
        result = self.execute(config)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])
        self.assertLess(time.monotonic() - started, 7)

    def test_continuous_polling_cleanup_has_no_async_callback_errors(self):
        config = {"engine": "browser", "limits": {"timeout_seconds": 1, "total_seconds": 4, "interval_seconds": 0.1},
                  "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "polling-cleanup", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/continuous-polling", "browser": {"wait_for_network_idle": True}},
                       "expect": {"contains": ["private-order-42"]}}]},
                      {"id": "fresh-context", "identity": "owner", "steps": [
                          {"request": {"url": self.origin + "/check"}, "expect": {"contains": ["anonymous"]}}]}]}
        errors = []
        started = time.monotonic()
        with patch.object(asyncio.BaseEventLoop, "call_exception_handler", side_effect=lambda context: errors.append(context)):
            result = self.execute(config)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])
        self.assertEqual(result["decisions"][1]["status"], "completed")
        self.assertFalse(errors, [e.get("message") for e in errors])
        self.assertLess(time.monotonic() - started, 8)

    def test_context_reset_and_repeated_close_dispose_old_session(self):
        sender = BrowserTransport({"owner": {"origin": self.origin}}, {"assets": [self.origin]}, timeout=1)
        old = sender.contexts["owner"]
        sender.reset("owner")
        self.assertIsNot(old, sender.contexts["owner"])
        sender.close()
        sender.close()
        self.assertFalse(sender.contexts)
        self.assertFalse(sender.pages)
        self.assertFalse(sender.pending)
        with self.assertRaises(RuntimeError):
            sender.reset("owner")
        with self.assertRaises(RuntimeError):
            sender("owner", {"url": self.origin})

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

    def test_supplied_cookie_credentials_rotate_without_leaking_to_other_context(self):
        config = {"engine": "browser", "identities": {"owner": {"origin": self.origin, "headers_env": {"Cookie": "MAHER_BROWSER_COOKIE"}},
                  "other": {"origin": self.origin}}, "workflows": [
                      {"id": "rotation", "identity": "owner", "steps": [
                          {"request": {"url": self.origin + "/check"}, "expect": {"contains": ["authenticated"]}},
                          {"request": {"url": self.origin + "/rotate"}, "expect": {"contains": ["rotated"]}},
                          {"request": {"url": self.origin + "/check"}, "expect": {"contains": ["authenticated"]}}]},
                      {"id": "other", "identity": "other", "steps": [
                          {"request": {"url": self.origin + "/check"}, "expect": {"contains": ["anonymous"]}}]}]}
        with patch.dict(os.environ, {"MAHER_BROWSER_COOKIE": "session=owner"}):
            result = self.execute(config)
        self.assertFalse(result["findings"])
        self.assertEqual(result["status"], "completed")
        cookies = [cookie for path, cookie in self.seen if path == "/check"]
        self.assertEqual(cookies, ["session=owner", "session=rotated", None])
