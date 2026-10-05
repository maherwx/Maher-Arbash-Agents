import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse
from urllib.error import URLError

from maher_bounty.workflow_execution import Transport, execute_workflows, validate_manifest


class LocalProxyTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                seen.append((self.path, self.headers.get("Cookie"), self.headers.get("Authorization")))
                path = urlparse(self.path).path
                self.send_response(302 if path == "/redirect" else 200)
                if path == "/login":
                    self.send_header("Set-Cookie", "session=fixture-owner; Path=/")
                if path == "/redirect":
                    self.send_header("Location", "https://outside.test/leak")
                self.end_headers()
                self.wfile.write(b'{"id":42}')
            def do_CONNECT(self):
                seen.append((self.path, self.headers.get("Cookie"), self.headers.get("Authorization")))
                self.send_error(502)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.proxy = {"url": f"http://127.0.0.1:{self.server.server_port}"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def test_explicit_proxy_ignores_no_proxy_and_preserves_cookie_isolation(self):
        origin = "http://app.example.test"
        identities = {name: {"origin": origin} for name in ["owner", "other"]}
        with patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
            sender = Transport(identities, proxy=self.proxy, interval=0)
            for name, path in [("owner", "/login"), ("owner", "/check"), ("other", "/check")]:
                sender(name, {"url": origin + path})
            sender.reset("owner")
            sender("owner", {"url": origin + "/check"})
        self.assertEqual(self.seen[1][1], "session=fixture-owner")
        self.assertIsNone(self.seen[2][1])
        self.assertIsNone(self.seen[3][1])
        self.assertTrue(all(url.startswith(origin) for url, *_ in self.seen))

    def test_https_uses_connect_without_sending_target_credentials_in_tunnel_headers(self):
        with patch.dict(os.environ, {"FIXTURE_AUTH": "Bearer fixture-secret"}):
            sender = Transport({"owner": {"origin": "https://app.example.test", "headers_env": {"Authorization": "FIXTURE_AUTH"}}},
                               proxy=self.proxy, interval=0)
        self.assertTrue(sender.tls_context.check_hostname)
        with self.assertRaises(URLError):
            sender("owner", {"url": "https://app.example.test/private"})
        self.assertEqual(self.seen, [("app.example.test:443", None, None)])

    def test_proxy_does_not_follow_redirect_or_expand_target_origin(self):
        origin = "http://app.example.test"
        sender = Transport({"owner": {"origin": origin}}, proxy=self.proxy, interval=0)
        self.assertEqual(sender("owner", {"url": origin + "/redirect"})["status"], 302)
        with self.assertRaises(ValueError):
            sender("owner", {"url": "http://outside.test/leak"})
        self.assertEqual(len(self.seen), 1)

    def test_manifest_execution_routes_through_proxy_and_keeps_evidence_secret_free(self):
        config = {"proxy": self.proxy, "identities": {"owner": {"origin": "http://app.example.test"}},
                  "workflows": [{"id": "read", "identity": "owner", "steps": [
                      {"request": {"url": "http://app.example.test/private"}, "expect": {"json_equals": {"/id": 42}}}]}]}
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": ["app.example.test"]}, td, authorized=True)
            self.assertEqual(result["decisions"][0]["status"], "completed")
            self.assertEqual(len(self.seen), 1)
            self.assertEqual(result, json.loads((Path(td) / "workflow-evidence.json").read_text()))

    def test_invalid_proxy_settings_rejected_before_network(self):
        urls = ["http://outside.test:8080", "http://192.168.1.2:8080", "http://localhost:8080", "https://127.0.0.1:8080",
                "http://user:pass@127.0.0.1:8080", "http://127.0.0.1", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?x=1"]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                Transport({"owner": {"origin": "http://app.example.test"}}, proxy={"url": url})
        config = {"engine": "browser", "proxy": self.proxy, "identities": {"owner": {"origin": "http://app.example.test"}},
                  "workflows": [{"id": "read", "identity": "owner", "steps": [{"request": {"url": "http://app.example.test/"}, "expect": {"statuses": [200]}}]}]}
        validate_manifest(config, {"assets": ["app.example.test"]})
        with tempfile.NamedTemporaryFile() as ca:
            config["proxy"] = {**self.proxy, "ca_file": ca.name}
            with self.assertRaises(ValueError):
                validate_manifest(config, {"assets": ["app.example.test"]})
        self.assertFalse(self.seen)


@unittest.skipUnless(os.environ.get("MAHER_BROWSER_TESTS") == "1", "opt-in real Chromium proxy fixture")
class BrowserProxyTests(unittest.TestCase):
    def test_navigation_javascript_identity_reset_and_scope_use_local_proxy(self):
        from maher_bounty.browser_runtime import BrowserTransport
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_CONNECT(self):
                self.send_response(200)
                self.end_headers()
                self.close_connection = False
                self.handle_one_request()
            def do_GET(self):
                seen.append(("http://app.example.test" + self.path if self.path.startswith("/") else self.path, self.headers.get("Cookie")))
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if urlparse(self.path).path == "/page":
                    body = b"<body><script>fetch('/state').then(()=>document.body.innerHTML='<div id=done>ready</div>')</script></body>"
                elif urlparse(self.path).path == "/blocked":
                    body = b"<body><script>fetch('http://outside.test/leak').catch(()=>document.body.innerHTML='<div id=done>ready</div>')</script></body>"
                else:
                    body = b"state"
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = "http://app.example.test"
        identities = {"owner": {"origin": origin, "headers_env": {"Cookie": "PROXY_FIXTURE_COOKIE"}}, "other": {"origin": origin}}
        try:
            with patch.dict(os.environ, {"PROXY_FIXTURE_COOKIE": "session=owner", "NO_PROXY": "*"}):
                sender = BrowserTransport(identities, {"assets": ["app.example.test"]}, interval=0,
                                          proxy={"url": f"http://127.0.0.1:{server.server_port}"})
                try:
                    for identity in ["owner", "other", "owner"]:
                        if len(seen) >= 4:
                            sender.reset("owner")
                        try:
                            result = sender(identity, {"url": origin + "/page", "browser": {"wait_for": "#done"}})
                        except RuntimeError as error:
                            self.fail(f"{error}; fixture traffic={seen}; summary={sender.summary()}")
                        self.assertEqual(result["status"], 200)
                        self.assertIn("ready", result["body"])
                    result = sender("owner", {"url": origin + "/blocked", "browser": {"wait_for": "#done"}})
                    self.assertTrue(result["network_incomplete"])
                    self.assertTrue(sender.summary()["local_proxy_enabled"])
                finally:
                    sender.close()
            self.assertEqual([cookie for _, cookie in seen[:6]], ["session=owner"] * 2 + [None] * 2 + ["session=owner"] * 2)
            self.assertTrue(all(url.startswith(origin) for url, _ in seen))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
