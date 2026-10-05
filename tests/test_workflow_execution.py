import copy
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from maher_bounty.workflow_execution import execute_workflows, Transport, validate_manifest
from maher_bounty.cli import main
from maher_bounty.orchestrator import _run_loaded
from maher_bounty.persistence import ResearchStore


def manifest(origin="https://app.example.test"):
    return {"identities": {name: {"origin": origin} for name in ["owner", "other", "anonymous"]},
            "access_cases": [{"id": "private-order", "request": {"url": origin + "/orders/42"},
                              "allowed": ["owner"], "denied": ["other", "anonymous"],
                              "proof": {"json_equals": {"/id": 42, "/owner": "owner"}}}]}


class WorkflowExecutionTests(unittest.TestCase):
    def run_case(self, config=None, sender=None):
        config = config or manifest()
        sender = sender or (lambda name, request: {"status": 200, "body": '{"id":42,"owner":"owner"}', "headers": {}})
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [config["identities"]["owner"]["origin"]]}, td,
                                       authorized=True, transport=sender)
            self.assertEqual(result, json.loads((Path(td) / "workflow-evidence.json").read_text()))
        return result

    def test_repeatable_private_object_access_is_evidence_backed(self):
        result = self.run_case()
        self.assertEqual(result["requests"], 6)
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(all(row["validated"] for row in result["findings"]))
        self.assertNotIn('"body":', json.dumps(result))

    def test_secure_policy_produces_no_finding(self):
        def sender(name, request):
            return {"status": 200 if name == "owner" else 403,
                    "body": '{"id":42,"owner":"owner"}' if name == "owner" else "denied", "headers": {}}
        self.assertFalse(self.run_case(sender=sender)["findings"])

    def test_access_finding_redacts_query_values_without_changing_requests(self):
        config = manifest()
        url = config["identities"]["owner"]["origin"] + "/orders/42?token=secret-value&token=second-secret&empty="
        config["access_cases"][0]["request"]["url"] = url
        sent = []
        def sender(name, request):
            sent.append(request["url"])
            return {"status": 200, "body": '{"id":42,"owner":"owner"}', "headers": {}}
        result = self.run_case(config, sender)
        self.assertEqual(sent, [url] * 6)
        self.assertEqual(len(result["findings"]), 2)
        for secret in ["secret-value", "second-secret"]:
            self.assertNotIn(secret, json.dumps(result))
        self.assertIn("token=%5Bredacted%5D&token=%5Bredacted%5D&empty=%5Bredacted%5D", result["findings"][0]["target"])

    def test_failed_workflow_redacts_static_query_and_capture_template(self):
        config = manifest()
        config["access_cases"] = []
        config["workflows"] = [{"id": "state", "identity": "owner", "variables": {"token": "captured-secret"}, "steps": [
            {"request": {"url": config["identities"]["owner"]["origin"] + "/state?fixed=static-secret&token={{token}}"},
             "expect": {"statuses": [403]}}]}]
        sent = []
        def sender(name, request):
            sent.append(request["url"])
            return {"status": 200, "body": "{}", "headers": {}}
        result = self.run_case(config, sender)
        self.assertIn("captured-secret", sent[0])
        self.assertEqual(result["decisions"][0]["status"], "invariant_failed")
        self.assertFalse(result["findings"][0]["validated"])
        for secret in ["static-secret", "captured-secret", "{{token}}"]:
            self.assertNotIn(secret, json.dumps(result))

    def test_login_html_and_success_status_are_not_resource_proof(self):
        def sender(name, request):
            return {"status": 200, "body": '{"id":42,"owner":"owner"}' if name == "owner" else "<html>Login</html>", "headers": {}}
        self.assertFalse(self.run_case(sender=sender)["findings"])

    def test_invalid_control_is_inconclusive(self):
        result = self.run_case(sender=lambda *_: {"status": 200, "body": "{}", "headers": {}})
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["findings"])

    def test_unstable_forbidden_result_is_not_confirmed(self):
        calls = {}
        def sender(name, request):
            calls[name] = calls.get(name, 0) + 1
            return {"status": 200 if name == "owner" or calls[name] == 1 else 403,
                    "body": '{"id":42,"owner":"owner"}', "headers": {}}
        self.assertFalse(self.run_case(sender=sender)["findings"])

    def test_truncated_control_and_budget_stop_without_confirmation(self):
        result = self.run_case(sender=lambda *_: {"status": 200, "body": '{"id":42,"owner":"owner"}', "truncated": True})
        self.assertEqual(result["status"], "partial")
        config = manifest()
        config["limits"] = {"max_requests": 1}
        result = self.run_case(config)
        self.assertEqual(result["requests"], 1)
        self.assertFalse(result["findings"])

    def test_truncated_denied_response_is_inconclusive_not_completed(self):
        for repeat in [1, 2]:
            for body in ['{"id":42,"owner":"owner"}', '{}']:
                with self.subTest(repeat=repeat, body=body):
                    calls = {}
                    def sender(name, request):
                        calls[name] = calls.get(name, 0) + 1
                        return {"status": 200, "body": body if name == "other" else '{"id":42,"owner":"owner"}',
                                "truncated": name == "other" and calls[name] == repeat}
                    result = self.run_case(sender=sender)
                    self.assertEqual(result["status"], "partial")
                    self.assertEqual(result["decisions"][0]["status"], "inconclusive")
                    self.assertEqual(result["requests"], 2 + repeat)
                    self.assertFalse(result["findings"])
                    self.assertTrue(result["observations"][0]["observations"][-1]["truncated"])

    def test_scope_and_origin_fail_before_requests(self):
        for url in ["https://outside.test/orders/42", "http://app.example.test/orders/42", "https://app.example.test:8443/orders/42"]:
            config = manifest()
            config["access_cases"][0]["request"]["url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.run_case(config)

    def test_missing_policy_proof_or_unknown_identity_is_rejected(self):
        for change in [{"proof": {}}, {"denied": ["missing"]}, {"denied": ["owner"]}]:
            config = manifest()
            config["access_cases"][0].update(change)
            with self.assertRaises(ValueError):
                self.run_case(config)

    def test_explicit_authorization_is_required(self):
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            execute_workflows(manifest(), {"assets": ["app.example.test"]}, td)

    def test_workflow_stops_on_first_failed_invariant(self):
        config = manifest()
        config["access_cases"] = []
        config["workflows"] = [{"id": "checkout-order", "identity": "owner", "steps": [
            {"request": {"url": "https://app.example.test/cart", "method": "POST", "body": {"quantity": 1}},
             "expect": {"json_equals": {"/state": "pending"}}},
            {"request": {"url": "https://app.example.test/checkout", "method": "POST"}, "expect": {"statuses": [403]}}]}]
        result = self.run_case(config, lambda *_: {"status": 200, "body": '{"state":"paid"}', "headers": {}})
        self.assertEqual(result["requests"], 1)
        self.assertFalse(result["findings"][0]["validated"])
        self.assertEqual(result["decisions"][0]["status"], "invariant_failed")

    def test_network_exception_does_not_persist_secret(self):
        def sender(*_):
            raise OSError("secret-credential")
        result = self.run_case(sender=sender)
        self.assertNotIn("secret-credential", json.dumps(result))

    def test_workflow_captures_object_id_and_passes_typed_json_values(self):
        config = manifest()
        config["access_cases"] = []
        config["workflows"] = [{"id": "create-then-read", "identity": "owner", "steps": [
            {"request": {"url": "https://app.example.test/orders", "method": "POST"},
             "expect": {"statuses": [201]}, "capture": {"order_id": "/id"}},
            {"request": {"url": "https://app.example.test/orders/{{order_id}}"},
             "expect": {"json_equals": {"/id": "{{order_id}}"}}}]}]
        seen = []
        def sender(name, request):
            seen.append(request)
            return {"status": 201 if len(seen) == 1 else 200, "body": '{"id":42}', "headers": {}}
        result = self.run_case(config, sender)
        self.assertEqual(seen[1]["url"], "https://app.example.test/orders/42")
        self.assertEqual(result["decisions"][0]["status"], "completed")
        self.assertFalse(result["findings"])

    def test_unresolved_variable_stops_workflow_before_request(self):
        config = manifest()
        config["access_cases"] = []
        config["workflows"] = [{"id": "missing-capture", "identity": "owner", "steps": [
            {"request": {"url": "https://app.example.test/{{missing}}"}, "expect": {"statuses": [200]}}]}]
        result = self.run_case(config)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["requests"], 0)


class LiveWorkflowTransportTests(unittest.TestCase):
    def test_real_bounded_denied_body_cannot_complete_access_case(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                body = b"private-order-42"
                if self.headers.get("X-Fixture-Role") != "owner":
                    body += b"x" * 100
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = manifest(f"http://127.0.0.1:{server.server_port}")
        config["access_cases"][0]["proof"] = {"contains": ["private-order-42"]}
        try:
            sender = Transport(config["identities"], max_bytes=32, interval=0)
            sender.headers["owner"]["X-Fixture-Role"] = "owner"
            result = WorkflowExecutionTests().run_case(config, sender)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["requests"], 3)
            self.assertFalse(result["findings"])
            row = result["observations"][0]["observations"][-1]
            self.assertTrue(row["truncated"])
            self.assertTrue(all(check["passed"] for check in row["assertions"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_real_http_isolated_cookie_jars_and_redirect_not_followed(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                seen.append((self.path, self.headers.get("Cookie")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/forbidden-follow")
                    self.end_headers()
                    return
                self.send_response(200)
                if self.path == "/login":
                    self.send_header("Set-Cookie", "session=owner; Path=/")
                self.end_headers()
                self.wfile.write(b'{"id":42,"owner":"owner"}')
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        config = manifest(origin)
        try:
            sender = Transport(config["identities"], interval=0, budget=10)
            sender("owner", {"url": origin + "/login"})
            sender("owner", {"url": origin + "/check"})
            sender("other", {"url": origin + "/check"})
            redirect = sender("owner", {"url": origin + "/redirect"})
            self.assertEqual(redirect["status"], 302)
            self.assertEqual(seen[1][1], "session=owner")
            self.assertIsNone(seen[2][1])
            self.assertNotIn("/forbidden-follow", [p for p, _ in seen])
            result = WorkflowExecutionTests().run_case(config, sender)
            self.assertEqual(result["requests"], 6)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_credential_environment_is_not_written_to_evidence(self):
        config = manifest()
        config["identities"]["owner"]["headers_env"] = {"Authorization": "MAHER_TEST_TOKEN"}
        with patch.dict(os.environ, {"MAHER_TEST_TOKEN": "Bearer secret-token"}):
            transport = Transport(config["identities"])
            self.assertEqual(transport.headers["owner"]["Authorization"], "Bearer secret-token")
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            Transport(config["identities"])


class WorkflowIntegrationTests(unittest.TestCase):
    def test_auto_run_passes_manifest_path(self):
        with patch.object(sys, "argv", ["maher-bounty", "auto-run", "--target", "https://app.example.test/",
                                       "--authorized", "--workflow-manifest", "assessment.json"]), \
                patch("maher_bounty.cli.run_target", return_value={}) as run:
            main()
        self.assertEqual(run.call_args.kwargs["workflow_manifest_path"], "assessment.json")

    def test_pipeline_merges_findings_and_writes_workflow_checkpoint(self):
        config = manifest()
        scope = {"assets": ["https://app.example.test/"]}
        workflow_result = {"status": "completed", "findings": [{"title": "Private order leaked", "source": "workflow_execution",
                            "target": "https://app.example.test/orders/42", "severity": "high", "validated": True,
                            "evidence": {"case_id": "private-order"}}]}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest_path = root / "assessment.json"
            manifest_path.write_text(json.dumps(config))
            inventory_path = root / "inventory.json"
            inventory_path.write_text(json.dumps({"hosts": [], "endpoints": [], "http": [], "counts": {}}))
            with patch("maher_bounty.orchestrator.ResearchStore", side_effect=lambda: ResearchStore(root / "research.db")), \
                    patch("maher_bounty.orchestrator.load_agents", return_value=[]), \
                    patch("maher_bounty.orchestrator.run_native_engines", return_value={}), \
                    patch("maher_bounty.orchestrator.run_active_testing", return_value={"status": "completed", "findings": []}), \
                    patch("maher_bounty.orchestrator.execute_workflows", return_value=workflow_result) as executor, \
                    patch("maher_bounty.orchestrator.run_agent_tool_requests", return_value={"runs": [], "findings": []}):
                result = _run_loaded(scope, {"authorization_required": True}, root / "out", inventory_path,
                                     authorized=True, workflow_manifest_path=manifest_path)
            self.assertEqual(result["workflow_execution"], workflow_result)
            self.assertEqual(result["validated_evidence"]["counts"]["evidence_backed"], 1)
            executor.assert_called_once()

    def test_invalid_manifest_fails_before_recon(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "manifest.json"
            path.write_text("{}")
            with patch("maher_bounty.orchestrator._collect_scope_inventory") as collector, self.assertRaises(ValueError):
                _run_loaded({"assets": ["https://app.example.test/"]}, {"authorization_required": True},
                            td, authorized=True, workflow_manifest_path=path)
            collector.assert_not_called()
