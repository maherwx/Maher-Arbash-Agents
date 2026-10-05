import json
import tempfile
import unittest
from unittest.mock import Mock
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from maher_bounty.workflow_execution import _assertions, _validate_expectation, execute_workflows, validate_manifest


class NumericInvariantTests(unittest.TestCase):
    def test_known_invalid_bound_blocks_all_traffic(self):
        origin = "https://app.example.test"
        for value in [True, "10", None, float("nan"), float("inf")]:
            config = {"identities": {"owner": {"origin": origin}}, "workflows": [{
                "id": "balance", "identity": "owner", "variables": {"limit": value}, "steps": [
                    {"request": {"url": origin, "method": "POST"}, "expect": {"statuses": [200]}},
                    {"request": {"url": origin}, "expect": {"json_number": {"/balance": {"lte": "{{limit}}"}}}}]}]}
            sender = Mock()
            with tempfile.TemporaryDirectory() as td, self.assertRaisesRegex(ValueError, "known json_number"):
                execute_workflows(config, {"assets": [origin]}, td, authorized=True, transport=sender)
            sender.assert_not_called()

    def test_capture_replaces_invalid_initial_bound(self):
        origin = "https://app.example.test"
        for kind in ["capture", "dom"]:
            first = {"request": {"url": origin}, "expect": {"statuses": [200]}}
            if kind == "capture":
                first["capture"] = {"limit": "/balance"}
            else:
                first["request"]["browser"] = {"capture_dom": {"limit": {"selector": "#balance"}}}
            config = {"engine": "browser" if kind == "dom" else "http",
                      "identities": {"owner": {"origin": origin}}, "workflows": [{
                          "id": "balance", "identity": "owner", "variables": {"limit": "unknown"},
                          "steps": [first, {"request": {"url": origin},
                                           "expect": {"json_number": {"/balance": {"lte": "{{limit}}"}}}}]}]}
            validate_manifest(config, {"assets": [origin]})

    def test_boundaries_and_strict_types(self):
        for value, passed in [(0, True), (5.5, True), (10, True), (-1, False),
                              (11, False), (True, False), ("5", False), (None, False)]:
            with self.subTest(value=value):
                checks = _assertions({"body": json.dumps({"balance": value})},
                                     {"json_number": {"/balance": {"gte": 0, "lte": 10}}})
                self.assertEqual(all(c["passed"] for c in checks), passed)
                self.assertTrue(all(set(c) == {"kind", "pointer", "operator", "passed"} for c in checks))
        for op, passed in [("gt", False), ("lt", False), ("gte", True), ("lte", True)]:
            self.assertEqual(_assertions({"body": "5"}, {"json_number": {"": {op: 5}}})[0]["passed"], passed)

    def test_invalid_json_and_missing_values_fail(self):
        for body in ["{}", "null", "garbage", '{"x":NaN}', '{"x":Infinity}', '{"x":1,"x":2}']:
            self.assertFalse(_assertions({"body": body}, {"json_number": {"/x": {"gte": 0}}})[0]["passed"])

    def test_invalid_bounds_and_operators_rejected(self):
        for bounds in [{}, {"eq": 1}, {"gte": True}, {"gte": "1"}, {"gte": float("inf")},
                       {"gte": float("nan")}, {"gte": None}, {"gte": "prefix{{value}}"}]:
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                _validate_expectation({"json_number": {"/x": bounds}}, allow_templates=True)
        _validate_expectation({"json_number": {"/x": {"lte": "{{initial}}"}}}, allow_templates=True)
        with self.assertRaises(ValueError):
            _validate_expectation({"json_number": {"/x": {"lte": "{{initial}}"}}})

    def run_workflow(self, initial, final, bound="{{initial}}"):
        origin = "https://app.example.test"
        config = {"identities": {"owner": {"origin": origin}}, "workflows": [{
            "id": "balance", "identity": "owner", "steps": [
                {"request": {"url": origin + "/balance"}, "expect": {"statuses": [200]},
                 "capture": {"initial": "/balance"}},
                {"request": {"url": origin + "/spend", "method": "POST"},
                 "expect": {"json_number": {"/balance": {"gte": 0, "lte": bound}}}}]}]}
        calls = []
        def sender(*args):
            calls.append(args)
            return {"status": 200, "headers": {}, "body": json.dumps({
                "balance": initial if len(calls) == 1 else final})}
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [origin]}, td, authorized=True, transport=sender)
        return result, calls

    def test_captured_numeric_bound_and_violation(self):
        for final, status in [(9, "completed"), (-1, "invariant_failed"), (11, "invariant_failed")]:
            result, calls = self.run_workflow(10, final)
            self.assertEqual(len(calls), 2)
            self.assertEqual(result["decisions"][0]["status"], status)
            if result["findings"]:
                self.assertFalse(result["findings"][0]["validated"])

    def test_nonnumeric_capture_prevents_mutation(self):
        result, calls = self.run_workflow("10", 9)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["decisions"][0]["status"], "inconclusive")
        self.assertFalse(result["findings"])

    def test_invalid_later_bound_preflight(self):
        with self.assertRaises(ValueError):
            self.run_workflow(10, 9, bound=True)

    def test_numeric_checks_alone_cannot_prove_resource_access(self):
        origin = "https://app.example.test"
        config = {"identities": {name: {"origin": origin} for name in ("owner", "other")},
                  "access_cases": [{"id": "balance", "allowed": ["owner"], "denied": ["other"],
                                    "request": {"url": origin},
                                    "proof": {"json_number": {"/balance": {"gte": 0}}}}]}
        with self.assertRaisesRegex(ValueError, "resource-specific"):
            validate_manifest(config, {"assets": [origin]})

    def test_real_http_numeric_state(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                payload = b'{"balance":-1}' if self.path == "/negative" else b'{"balance":9}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = "http://127.0.0.1:" + str(server.server_port)
        try:
            for path, status in [("/positive", "completed"), ("/negative", "invariant_failed")]:
                config = {"identities": {"owner": {"origin": origin}}, "workflows": [{
                    "id": "balance", "identity": "owner", "steps": [{
                        "request": {"url": origin + path},
                        "expect": {"json_number": {"/balance": {"gte": 0, "lte": 10}}}}]}]}
                with tempfile.TemporaryDirectory() as td:
                    result = execute_workflows(config, {"assets": [origin]}, td, authorized=True)
                self.assertEqual(result["decisions"][0]["status"], status)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)
