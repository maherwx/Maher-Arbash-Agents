import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from maher_bounty.workflow_execution import _assertions, execute_workflows


def workflow(expect, capture=None):
    origin = "https://app.example.test"
    step = {"request": {"url": origin}, "expect": expect}
    if capture is not None:
        step["capture"] = capture
    return {"identities": {"owner": {"origin": origin}}, "workflows": [{"id": "state", "identity": "owner", "steps": [step]}]}


class JsonStateAbsenceTests(unittest.TestCase):
    def test_missing_fields_are_distinct_from_null_and_invalid_structure(self):
        cases = [('{}', '/token', True), ('{"token":null}', '/token', False),
                 ('{"state":{}}', '/state/token', True), ('{"state":null}', '/state/token', False),
                 ('[]', '/0', True), ('[]', '/-1', False), ('null', '/token', False)]
        for body, pointer, expected in cases:
            with self.subTest(body=body, pointer=pointer):
                self.assertEqual(_assertions({"body": body}, {"json_absent": [pointer]})[0]["passed"], expected)

    def test_invalid_or_ambiguous_json_never_proves_absence(self):
        for body in ['<html>login</html>', '', '{"id":1,"id":2}', '{"state":NaN}']:
            with self.subTest(body=body):
                self.assertFalse(_assertions({"body": body}, {"json_absent": ["/token"]})[0]["passed"])

    def test_invalid_pointers_and_capture_formats_fail_before_traffic(self):
        configs = [workflow({"json_absent": "token"}), workflow({"json_absent": []}),
                   workflow({"json_absent": ["/token~2"]}), workflow({"json_equals": {"/x~": 1}}),
                   workflow({"statuses": [200]}, []), workflow({"statuses": [200]}, {"id": "/bad~3"}),
                   workflow({"statuses": [200]}, {"bad-name": "/id"})]
        for config in configs:
            with self.subTest(config=config), tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
                execute_workflows(config, {"assets": ["app.example.test"]}, td, authorized=True,
                                  transport=lambda *_: self.fail("must not issue traffic"))
        checks = _assertions({"body": '{"a/b":{"~key":1}}'},
                             {"json_equals": {"/a~1b/~0key": 1}, "json_absent": ["/a~1b/missing"]})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_absence_alone_is_not_resource_access_proof(self):
        config = {"identities": {n: {"origin": "https://app.example.test"} for n in ["owner", "other"]},
                  "access_cases": [{"id": "private", "allowed": ["owner"], "denied": ["other"],
                                    "request": {"url": "https://app.example.test"}, "proof": {"json_absent": ["/token"]}}]}
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            execute_workflows(config, {"assets": ["app.example.test"]}, td, authorized=True,
                              transport=lambda *_: self.fail("must not issue traffic"))

    def test_revocation_cycle_checks_absence_without_persisting_secret(self):
        state = {"revoked": False}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def respond(self):
                body = {"id": "42", "state": "revoked" if state["revoked"] else "active"}
                if not state["revoked"]:
                    body["private_token"] = "fixture-secret-value"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())
            def do_GET(self):
                self.respond()
            def do_POST(self):
                state["revoked"] = True
                self.respond()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        config = {"identities": {"owner": {"origin": origin}}, "workflows": [{"id": "revoke", "identity": "owner", "steps": [
            {"request": {"url": origin + "/state"}, "expect": {"json_equals": {"/state": "active"}}, "capture": {"id": "/id"}},
            {"request": {"url": origin + "/revoke", "method": "POST"}, "expect": {"json_equals": {"/state": "revoked"}}},
            {"request": {"url": origin + "/state"}, "expect": {"statuses": [200], "json_equals": {"/id": "{{id}}", "/state": "revoked"},
                                                               "json_absent": ["/private_token"]}}]}]}
        try:
            with tempfile.TemporaryDirectory() as td:
                result = execute_workflows(config, {"assets": [origin]}, td, authorized=True)
                evidence = (Path(td) / "workflow-evidence.json").read_text()
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["requests"], 3)
            self.assertFalse(result["findings"])
            self.assertNotIn("fixture-secret-value", evidence)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
