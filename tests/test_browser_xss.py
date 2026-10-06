import html
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from maher_bounty.browser_xss import run_browser_xss
from maher_bounty.agent_tool_router import run_agent_tool_requests, _prior_coverage


class BrowserXssPreflightTests(unittest.TestCase):
    def test_authorization_and_scope_before_browser_start(self):
        with patch("maher_bounty.browser_runtime.BrowserTransport") as browser:
            with self.assertRaises(ValueError):
                run_browser_xss("https://example.test/?q=x", ".", scope={"assets": ["https://example.test"]})
            with self.assertRaises(ValueError):
                run_browser_xss("https://outside.test/?q=x", ".", scope={"assets": ["https://example.test"]}, authorized=True)
            browser.assert_not_called()

    def test_oversized_parameter_inventory_is_blocked_before_browser(self):
        with patch("maher_bounty.browser_runtime.BrowserTransport") as browser:
            result = run_browser_xss("https://example.test/?" + "&".join("p=x" for _ in range(101)), ".",
                                     scope={"assets": ["https://example.test"]}, authorized=True)
        self.assertEqual(result["status"], "blocked")
        browser.assert_not_called()


@unittest.skipUnless(os.environ.get("MAHER_BROWSER_TESTS") == "1", "opt-in real Chromium fixtures")
class BrowserXssExecutionTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                parsed = urlsplit(self.path)
                seen.append(parsed.path)
                value = parse_qs(parsed.query).get("q", [""])[0]
                if parsed.path == "/escaped" or (parsed.path == "/once" and seen.count("/once") >= 3):
                    value = html.escape(value)
                body = ("<html><body>" + value + "</body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if parsed.path == "/csp":
                    self.send_header("Content-Security-Policy", "script-src 'none'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.scope = {"assets": [self.origin]}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)

    def test_real_agent_router_confirms_two_executions_and_reuses_coverage(self):
        url = self.origin + "/vulnerable?q=fixture-secret"
        with tempfile.TemporaryDirectory() as td:
            result = run_agent_tool_requests([{"agent": "fixture-xss-specialist", "tool_requests": [
                {"tool": "browser-xss", "targets": [url]}]}], [url], td, scope=self.scope)
            self.assertEqual(len(result["findings"]), 1)
            finding = result["findings"][0]
            self.assertTrue(finding["validated"])
            self.assertEqual(len(finding["evidence"]["proofs"]), 2)
            self.assertNotEqual(*[proof["token"] for proof in finding["evidence"]["proofs"]])
            self.assertNotIn("fixture-secret", json.dumps(result))
            self.assertIn(url, _prior_coverage(result, {url})["browser-xss"])
            self.assertEqual(len(self.seen), 3)

    def test_escaped_and_csp_controls_do_not_confirm(self):
        for path in ["escaped", "csp"]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as td:
                result = run_browser_xss(self.origin + "/" + path + "?q=test", td,
                                         scope=self.scope, authorized=True)
                self.assertEqual(result["status"], "ok")
                self.assertFalse(result["findings"])
                self.assertEqual(result["checks"][0]["status"], "not_confirmed")

    def test_single_execution_is_not_repeatable_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            result = run_browser_xss(self.origin + "/once?q=test", td, scope=self.scope, authorized=True)
        self.assertFalse(result["findings"])
        self.assertEqual(len(result["checks"][0]["proofs"]), 1)
        self.assertEqual(result["checks"][0]["status"], "not_confirmed")
