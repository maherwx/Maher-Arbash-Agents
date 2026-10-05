import tempfile
import unittest
from unittest.mock import patch
from maher_bounty.agent_feedback import run_agent_tool_feedback


class AgentFeedbackTests(unittest.TestCase):
    origin = "https://app.example.test/"
    def request(self, tool, urls):
        return [{"agent": "fixture-specialist", "tool_requests": [{"tool": tool, "targets": urls}]}]

    def test_new_query_is_planned_after_discovery_without_repeating_failed_tool(self):
        fresh = self.origin + "search?q=test"
        observed = []
        def execute(rows, known, out, **kwargs):
            observed.append((rows, list(known), kwargs))
            return {"request_count": 1, "new_in_scope_urls": [fresh] if len(observed) == 1 else [],
                    "runs": [{"tool": "katana", "status": "timeout", "target": self.origin}],
                    "findings": [], "decisions": []}
        plan = {"agent_results": self.request("katana", [self.origin]) + self.request("dalfox", [fresh])}
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_feedback.run_agent_tool_requests", side_effect=execute), \
             patch("maher_bounty.agent_feedback.build_local_tool_requests", return_value=plan):
            result = run_agent_tool_feedback(self.request("katana", [self.origin]), [self.origin], td,
                                             scope={"assets": [self.origin]})
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[1][0][0]["tool_requests"][0]["tool"], "dalfox")
        self.assertIn(fresh, observed[1][1])
        self.assertEqual(observed[1][2]["active_testing"]["runs"][0]["status"], "timeout")
        self.assertEqual(result["stop_reason"], "no_new_in_scope_evidence")

    def test_real_deterministic_planner_queues_parameter_scanner_for_new_route(self):
        fresh = self.origin + "search?q=fixture"
        batches = []
        def execute(rows, known, out, **kwargs):
            batches.append((rows, list(known)))
            return {"request_count": 1, "new_in_scope_urls": [fresh] if len(batches) == 1 else [],
                    "runs": [{"tool": "katana", "status": "ok", "command": ["katana"]}],
                    "findings": [], "decisions": []}
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_feedback.run_agent_tool_requests", side_effect=execute), \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/local-tool"):
            result = run_agent_tool_feedback(self.request("katana", [self.origin]), [self.origin], td,
                                             scope={"assets": [self.origin]})
        self.assertEqual(len(batches), 2)
        followup = [request for row in batches[1][0] for request in row["tool_requests"]]
        self.assertTrue(any(row["tool"] == "dalfox" and fresh in row["targets"] for row in followup))
        self.assertIn(fresh, batches[1][1])
        self.assertEqual(result["rounds"][0]["new_url_count"], 1)
        self.assertEqual(result["stop_reason"], "no_new_in_scope_evidence")

    def test_scope_rejection_stops_feedback(self):
        with tempfile.TemporaryDirectory() as td, patch("maher_bounty.agent_feedback.run_agent_tool_requests", return_value={
                "new_in_scope_urls": ["https://outside.example/"], "runs": [], "findings": []}) as execute:
            result = run_agent_tool_feedback(self.request("katana", [self.origin]), [self.origin], td,
                                             scope={"assets": [self.origin]})
        self.assertEqual(execute.call_count, 1)
        self.assertFalse(result["new_in_scope_urls"])

    def test_global_route_admission_budget(self):
        fresh = [self.origin + str(i) for i in range(40)]
        with tempfile.TemporaryDirectory() as td, patch("maher_bounty.agent_feedback.run_agent_tool_requests", return_value={
                "new_in_scope_urls": fresh, "runs": [], "findings": []}), \
             patch("maher_bounty.agent_feedback.build_local_tool_requests", return_value={"agent_results": []}):
            result = run_agent_tool_feedback(self.request("katana", [self.origin]), [self.origin], td,
                                             scope={"assets": [self.origin]})
        self.assertEqual(len(result["new_in_scope_urls"]), 30)
        self.assertEqual(result["stop_reason"], "no_unattempted_requests")

    def test_round_budget_and_evidence_preservation(self):
        counter = []
        def execute(*args, **kwargs):
            counter.append(1)
            return {"new_in_scope_urls": [self.origin + str(len(counter))], "runs": [],
                    "findings": [{"title": str(len(counter))}]}
        def plan(known, **kwargs):
            return {"agent_results": self.request("nuclei", [known[-1]])}
        with tempfile.TemporaryDirectory() as td, patch("maher_bounty.agent_feedback.run_agent_tool_requests", side_effect=execute), \
             patch("maher_bounty.agent_feedback.build_local_tool_requests", side_effect=plan):
            result = run_agent_tool_feedback(self.request("nuclei", [self.origin]), [self.origin], td,
                                             scope={"assets": [self.origin]})
        self.assertEqual(len(counter), 3)
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(result["stop_reason"], "round_limit")

    def test_invalid_round_budget_before_execution(self):
        for value in [True, 0, 4, 1.5]:
            with self.assertRaises(ValueError):
                run_agent_tool_feedback([], [], ".", scope={}, max_rounds=value)
