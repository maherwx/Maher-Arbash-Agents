import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from maher_bounty.workflow_execution import Transport, execute_workflows


class HttpReadBudgetTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                seen.append(self.path)
                self.send_response(403 if self.path == "/denied" else 200)
                self.send_header("Content-Type", "text/plain")
                if self.path == "/chunk-drip":
                    self.send_header("Transfer-Encoding", "chunked")
                sizes = {"/ok": 13, "/denied": 6, "/large": 2000, "/short": 100}
                if self.path in sizes:
                    self.send_header("Content-Length", str(sizes[self.path]))
                self.end_headers()
                try:
                    if self.path == "/chunk-drip":
                        for _ in range(100):
                            self.wfile.write(b"f")
                            self.wfile.flush()
                            time.sleep(0.03)
                    elif self.path == "/drip":
                        for _ in range(100):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                            time.sleep(0.03)
                    elif self.path == "/large":
                        self.wfile.write(b"x" * 2000)
                    else:
                        self.wfile.write(b"private-state" if self.path in {"/ok", "/short"} else b"denied")
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def sender(self, **options):
        return Transport({"owner": {"origin": self.origin}}, interval=0, **options)

    def test_slow_drip_body_cannot_reset_elapsed_read_budget(self):
        sender = self.sender(timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            sender("owner", {"url": self.origin + "/drip"})
        self.assertLess(time.monotonic() - started, 0.9)

    def test_rate_delay_rechecks_run_deadline_before_network(self):
        sender = self.sender(deadline=time.monotonic() + 0.03)
        sender.interval = 0.08
        sender.last = time.monotonic()
        with self.assertRaises(RuntimeError):
            sender("owner", {"url": self.origin + "/ok"})
        self.assertEqual(sender.count, 0)
        self.assertFalse(self.seen)

    def test_slow_chunk_framing_cannot_reset_body_deadline(self):
        sender = self.sender(timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            sender("owner", {"url": self.origin + "/chunk-drip"})
        self.assertLess(time.monotonic() - started, 0.9)

    def test_error_response_and_body_truncation_keep_semantics(self):
        sender = self.sender(max_bytes=64)
        self.assertEqual(sender("owner", {"url": self.origin + "/ok"})["body"], "private-state")
        denied = sender("owner", {"url": self.origin + "/denied"})
        self.assertEqual(denied["status"], 403)
        self.assertEqual(denied["body"], "denied")
        large = sender("owner", {"url": self.origin + "/large"})
        self.assertTrue(large["truncated"])
        self.assertEqual(len(large["body"]), 64)

    def test_drip_workflow_is_inconclusive_without_partial_findings(self):
        config = {"limits": {"timeout_seconds": 1}, "identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "drip", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/drip"}, "expect": {"contains": ["x"]}}]}]}
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [self.origin]}, td, authorized=True)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])
        self.assertLess(time.monotonic() - started, 2)

    def test_premature_eof_cannot_confirm_matching_private_marker(self):
        config = {"identities": {"owner": {"origin": self.origin}},
                  "workflows": [{"id": "short", "identity": "owner", "steps": [
                      {"request": {"url": self.origin + "/short"}, "expect": {"contains": ["private-state"]}}]}]}
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [self.origin]}, td, authorized=True)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])
