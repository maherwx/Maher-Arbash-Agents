"""Live loopback-only evaluation of explicit access and state policies."""
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .workflow_execution import execute_workflows


CASES = (
    ("secure_access", "clean"),
    ("cross_user_access", "confirmed_access"),
    ("anonymous_access", "confirmed_access"),
    ("soft_login", "clean"),
    ("unstable_access", "inconclusive"),
    ("invalid_baseline", "inconclusive"),
    ("protected_state", "clean"),
    ("unprotected_state", "workflow_candidate"),
)


def _outcome(result):
    if any(row.get("validated") for row in result["findings"]):
        return "confirmed_access"
    if result["findings"]:
        return "workflow_candidate"
    return "inconclusive" if result["status"] == "partial" else "clean"


def run_workflow_benchmark(out_dir, *, engine="http"):
    if engine not in {"http", "browser"}:
        raise ValueError("benchmark engine must be http or browser")
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    fixture = {"case": "", "state": "private", "calls": {}}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def reply(self, status, body, content_type="application/json"):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def actor(self):
            cookie = self.headers.get("Cookie", "")
            return "owner" if cookie == "session=fixture-owner" else "other" if cookie == "session=fixture-other" else "anonymous"
        def do_GET(self):
            if self.path == "/favicon.ico":
                self.reply(204, "")
                return
            if self.path == "/edit/42" and engine == "browser":
                self.reply(200, "<body><input id=value><button id=submit>submit</button><script>document.querySelector('#submit').onclick=()=>fetch('/objects/42',{method:'PATCH',body:document.querySelector('#value').value}).then(()=>document.body.innerHTML='<div id=done>submitted</div>')</script></body>", "text/html")
                return
            if self.path != "/objects/42":
                self.reply(404, '{}')
                return
            actor, case = self.actor(), fixture["case"]
            fixture["calls"][actor] = fixture["calls"].get(actor, 0) + 1
            allowed = actor == "owner"
            if case == "cross_user_access" and actor == "other":
                allowed = True
            if case == "anonymous_access" and actor == "anonymous":
                allowed = True
            if case == "unstable_access" and actor == "other":
                allowed = fixture["calls"][actor] % 2 == 1
            if case == "invalid_baseline" and actor == "owner":
                self.reply(200, '{}')
            elif allowed:
                if engine == "browser":
                    self.reply(200, '<body><div id=object-id>42</div><div>private-resource-42 state=' + fixture["state"] + '</div></body>', "text/html")
                else:
                    self.reply(200, json.dumps({"id": 42, "owner": "owner", "state": fixture["state"]}))
            elif case == "soft_login":
                self.reply(200, "<body>Sign in to continue</body>", "text/html")
            else:
                self.reply(403, '{"error":"denied"}')
        def do_PATCH(self):
            # Fixed local fixture endpoint, bounded body, no outbound activity.
            if self.path != "/objects/42":
                self.reply(404, '{}')
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size > 1024:
                self.reply(413, '{}')
                return
            raw = self.rfile.read(size).decode("utf-8", errors="replace")
            allowed = self.actor() == "owner" or fixture["case"] == "unprotected_state"
            if allowed:
                try:
                    supplied = json.loads(raw)
                except ValueError:
                    supplied = raw
                state = supplied.get("state") if isinstance(supplied, dict) else supplied
                if not isinstance(state, str) or state not in {"private", "tampered"}:
                    self.reply(400, '{}')
                    return
                fixture["state"] = state
            self.reply(200 if allowed else 403, '{}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    prefix = "MAHER_BENCH_" + uuid.uuid4().hex.upper()
    env = {prefix + "_OWNER": "session=fixture-owner", prefix + "_OTHER": "session=fixture-other"}
    identities = {"owner": {"origin": origin, "headers_env": {"Cookie": prefix + "_OWNER"}},
                  "other": {"origin": origin, "headers_env": {"Cookie": prefix + "_OTHER"}},
                  "anonymous": {"origin": origin}}
    results = []
    os.environ.update(env)
    try:
        for name, expected in CASES:
            fixture.update(case=name, state="private", calls={})
            config = {"engine": engine, "identities": identities,
                      "limits": {"timeout_seconds": 5, "total_seconds": 30, "max_requests": 40, "interval_seconds": 0.1}}
            proof = {"contains": ["private-resource-42"]} if engine == "browser" else {"json_equals": {"/id": 42, "/owner": "owner"}}
            if name.endswith("state"):
                first = {"request": {"url": origin + "/objects/42"}, "expect": {"statuses": [200], **proof}}
                if engine == "browser":
                    first["request"]["browser"] = {"capture_dom": {"id": {"selector": "#object-id"}}}
                    edit = {"identity": "other", "request": {"url": origin + "/edit/{{id}}", "browser": {
                        "actions": [{"kind": "fill", "selector": "#value", "value": "tampered"}, {"kind": "click", "selector": "#submit"}],
                        "wait_for": "#done", "wait_for_network_idle": True}}, "expect": {"contains": ["submitted"]}}
                    final_proof = {"contains": ["state=private"]}
                else:
                    first["capture"] = {"id": "/id"}
                    edit = {"identity": "other", "request": {"url": origin + "/objects/{{id}}", "method": "PATCH", "body": {"state": "tampered"}}, "expect": {"statuses": [200, 403]}}
                    final_proof = {"json_equals": {"/state": "private"}}
                config["workflows"] = [{"id": name, "identity": "owner", "steps": [first, edit,
                    {"request": {"url": origin + "/objects/{{id}}"}, "expect": {"statuses": [200], **final_proof}}]}]
                if engine == "browser":
                    restore = {"request": {"url": origin + "/edit/{{id}}", "browser": {
                        "actions": [{"kind": "fill", "selector": "#value", "value": "private"}, {"kind": "click", "selector": "#submit"}],
                        "wait_for": "#done", "wait_for_network_idle": True}}, "expect": {"contains": ["submitted"]}}
                else:
                    restore = {"request": {"url": origin + "/objects/{{id}}", "method": "PATCH", "body": {"state": "private"}}, "expect": {"statuses": [200]}}
                config["workflows"][0]["cleanup_steps"] = [restore,
                    {"request": {"url": origin + "/objects/{{id}}"}, "expect": {"statuses": [200], **final_proof}}]
            else:
                config["access_cases"] = [{"id": name, "allowed": ["owner"], "denied": ["other", "anonymous"],
                    "request": {"url": origin + "/objects/42"}, "proof": proof}]
            try:
                evidence = execute_workflows(config, {"assets": [origin]}, root / name, authorized=True)
                observed = _outcome(evidence)
                results.append({"case": name, "expected": expected, "observed": observed,
                                "passed": observed == expected, "requests": evidence["requests"],
                                "confirmed_findings": sum(bool(f.get("validated")) for f in evidence["findings"]),
                                "candidate_findings": sum(not f.get("validated") for f in evidence["findings"])})
                if name.endswith("state"):
                    verified = fixture["state"] == "private" and all(row["status"] == "completed" for row in evidence.get("cleanup_decisions", [])) and bool(evidence.get("cleanup_decisions"))
                    results[-1]["cleanup_verified"] = verified
                    results[-1]["passed"] = results[-1]["passed"] and verified
            except Exception as error:
                results.append({"case": name, "expected": expected, "observed": "execution_error",
                                "passed": False, "error_type": type(error).__name__})
    finally:
        for key in env:
            os.environ.pop(key, None)
        server.shutdown()
        server.server_close()
        thread.join(2)
    summary = {"schema_version": "1.0", "engine": engine, "scope": "generated_loopback_fixture",
               "case_count": len(results), "passed": sum(row["passed"] for row in results),
               "failed": sum(not row["passed"] for row in results), "results": results}
    summary["quality"] = {
        "confirmed_access_expected": sum(row["expected"] == "confirmed_access" for row in results),
        "confirmed_access_detected": sum(row["expected"] == row["observed"] == "confirmed_access" for row in results),
        "state_candidates_expected": sum(row["expected"] == "workflow_candidate" for row in results),
        "state_candidates_detected": sum(row["expected"] == row["observed"] == "workflow_candidate" for row in results),
        "false_positive_cases": sum(row["expected"] in {"clean", "inconclusive"} and row["observed"] in {"confirmed_access", "workflow_candidate"} for row in results),
        "inconclusive_controls_preserved": sum(row["expected"] == row["observed"] == "inconclusive" for row in results),
        "clean_controls_preserved": sum(row["expected"] == row["observed"] == "clean" for row in results),
    }
    summary["quality_gate_passed"] = summary["failed"] == 0
    (root / "workflow-benchmark.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
