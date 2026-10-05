import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.agent_tool_router import build_local_tool_requests, run_agent_tool_requests


class AgentToolRouterTests(unittest.TestCase):
    def test_local_coordinator_selects_uncovered_tools_without_a_model(self):
        root = "https://app.example.test/"
        query = "https://app.example.test/search?q=blue"
        plan = build_local_tool_requests(
            [root, query],
            scope={"assets": [root], "out_of_scope": []},
            active_testing={"runs": [{
                "tool": "nmap", "status": "ok",
                "command": ["nmap", "-sV", "-Pn", "--top-ports", "100", "app.example.test"],
            }]},
            tool_plan={"runs": [{
                "tool": "subfinder", "status": "ok",
                "command": ["subfinder", "-silent", "-d", "app.example.test"],
            }]},
        )
        requests = [
            item for result in plan["agent_results"]
            for item in result["tool_requests"]
        ]
        names = {item["tool"] for item in requests}
        self.assertIn("dalfox", names)
        self.assertIn("naabu", names)
        self.assertNotIn("nmap", names)
        self.assertNotIn("subfinder", names)
        self.assertLessEqual(plan["request_count"], 20)
        self.assertTrue(all(target in {root, query} for item in requests for target in item["targets"]))
        self.assertEqual(plan["mode"], "local_deterministic_evidence_coordinator")

    def test_only_allowlisted_tools_and_known_in_scope_urls_run(self):
        safe = "https://app.example.test/search?q=one"
        outside = "https://attacker.example/path"
        results = [
            {"agent": "xss_reviewer", "tool_requests": [
                {"tool": "dalfox", "targets": [safe, outside, "https://app.example.test/unseen"], "reason": "query parameter observed"},
                {"tool": "shell", "targets": [safe], "reason": "not allowlisted"},
            ]}
        ]
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec", return_value={"tool": "dalfox", "status": "ok"}) as execute:
            summary = run_agent_tool_requests(
                results, [safe], td,
                scope={"assets": ["https://app.example.test"], "out_of_scope": []},
            )
            self.assertEqual(len(execute.call_args_list), 1)
            command = execute.call_args.args[0]
            self.assertIn("dalfox", command)
            target_file = Path(command[2])
            self.assertEqual(target_file.read_text(encoding="utf-8").strip(), safe)
            self.assertEqual(summary["runs"][0]["status"], "ok")
            self.assertTrue(any(row["status"] == "rejected" for row in summary["decisions"]))
            self.assertEqual(summary["findings"], [])

    def test_agents_can_select_fixed_http_tools_on_exact_known_urls(self):
        route = "https://app.example.test/account?view=summary"
        results = [{"agent": "tech_reviewer", "tool_requests": [
            {"tool": "whatweb", "targets": [route], "reason": "fingerprint observed headers"}
        ]}]
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec", return_value={"tool": "whatweb", "status": "ok"}) as execute:
            summary = run_agent_tool_requests(
                results, [route], td,
                scope={"assets": ["https://app.example.test"], "out_of_scope": []},
            )
        command = execute.call_args.args[0]
        self.assertEqual(command[0], "whatweb")
        self.assertEqual(command[-1], route)
        self.assertEqual(summary["runs"][0]["target"], route)

    def test_alterx_routes_only_resolved_in_scope_hosts_to_http_and_nuclei(self):
        seed = "https://app.example.test/"
        resolved = "api.app.example.test"
        discovered = "https://api.app.example.test/"

        dnsx_inputs = []
        def fake_exec(command, **kwargs):
            output = kwargs.get("output")
            if command[0] == "dnsx":
                dnsx_inputs.append(kwargs.get("input_text"))
            if command[0] == "alterx":
                output.write_text(resolved + "\napi.outside.test\n", encoding="utf-8")
            elif command[0] == "dnsx":
                output.write_text(resolved + " [A] 192.0.2.10\n", encoding="utf-8")
            elif command[0] == "httpx":
                output.write_text('{"url":"' + discovered + '"}\n', encoding="utf-8")
            return {"tool": command[0], "status": "ok", "command": command}

        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec", side_effect=fake_exec) as execute:
            summary = run_agent_tool_requests(
                [{"agent": "subdomain_reviewer", "tool_requests": [{
                    "tool": "alterx", "targets": [seed], "reason": "known host pattern",
                }]}],
                [seed], td,
                scope={"assets": [seed, "*.example.test"], "out_of_scope": ["*.outside.test"]},
            )
        commands = [call.args[0] for call in execute.call_args_list]
        self.assertEqual([command[0] for command in commands], ["alterx", "dnsx", "httpx", "nuclei"])
        self.assertEqual(dnsx_inputs, [resolved + "\n"])
        self.assertEqual(summary["new_in_scope_urls"], [discovered])

    def test_reuses_passive_subfinder_coverage_from_inventory(self):
        target = "https://app.example.test/"
        plan = {"runs": [{
            "tool": "subfinder", "status": "ok",
            "command": ["subfinder", "-silent", "-d", "app.example.test"],
        }]}
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec") as execute:
            summary = run_agent_tool_requests(
                [{"agent": "domain_reviewer", "tool_requests": [{
                    "tool": "subfinder", "targets": [target],
                }]}],
                [target], td,
                scope={"assets": [target], "out_of_scope": []},
                tool_plan=plan,
            )
        execute.assert_not_called()
        self.assertTrue(any(
            row.get("reason") == "already_covered_in_base_scan"
            for row in summary["decisions"]
        ))

    def test_naabu_uses_fixed_scoped_host_profile(self):
        target = "https://app.example.test/account"
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec", return_value={"tool": "naabu", "status": "ok"}) as execute:
            run_agent_tool_requests(
                [{"agent": "network_reviewer", "tool_requests": [{
                    "tool": "naabu", "targets": [target],
                }]}],
                [target], td,
                scope={"assets": ["https://app.example.test"], "out_of_scope": []},
            )
        command = execute.call_args.args[0]
        self.assertEqual(command[:2], ["naabu", "-host"])
        self.assertEqual(command[2], "app.example.test")
        self.assertIn("100", command)
        self.assertIn("10", command)

    def test_ffuf_discovery_is_scope_filtered_then_drives_new_url_scan(self):
        target = "https://app.example.test/"
        fresh = "https://app.example.test/new-route"
        outside = "https://outside.example/new-route"
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._directory_discovery", return_value=[fresh, outside]) as discover, \
             patch("maher_bounty.agent_tool_router._exec", return_value={"tool": "nuclei", "status": "ok"}) as execute:
            summary = run_agent_tool_requests(
                [{"agent": "route_reviewer", "tool_requests": [{
                    "tool": "ffuf", "targets": [target], "reason": "test safe route candidates",
                }]}],
                [target], td,
                scope={"assets": [target], "out_of_scope": []},
            )
            target_lines = Path(execute.call_args.args[0][2]).read_text(encoding="utf-8").splitlines()
        self.assertEqual(discover.call_args.kwargs["preferred_tool"], "ffuf")
        self.assertEqual(execute.call_args.args[0][0], "nuclei")
        self.assertEqual(target_lines, [fresh])
        self.assertEqual(summary["new_in_scope_urls"], [fresh])
        self.assertNotIn(outside, summary["new_in_scope_urls"])

    def test_burp_reference_runs_exact_url_without_exposing_value_to_model(self):
        exact_url = "https://app.example.test/search?token=secret-value"
        reference = "local-ref-1"
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec", return_value={"tool": "whatweb", "status": "ok"}) as execute:
            run_agent_tool_requests(
                [{"agent": "traffic_reviewer", "tool_requests": [{
                    "tool": "whatweb", "target_refs": [reference],
                }]}],
                [exact_url], td,
                scope={"assets": ["https://app.example.test"], "out_of_scope": []},
                target_references={reference: exact_url},
            )
        command = execute.call_args.args[0]
        self.assertEqual(command[-1], exact_url)

    def test_reuses_nmap_host_coverage_from_base_run(self):
        route = "https://app.example.test/profile"
        active = {"runs": [{
            "tool": "nmap", "status": "ok",
            "command": ["nmap", "-sV", "-Pn", "--top-ports", "100", "app.example.test"],
        }]}
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec") as execute:
            summary = run_agent_tool_requests(
                [{"agent": "network_reviewer", "tool_requests": [
                    {"tool": "nmap", "targets": [route]}
                ]}],
                [route], td,
                scope={"assets": ["https://app.example.test"], "out_of_scope": []},
                active_testing=active,
            )
        execute.assert_not_called()
        self.assertTrue(any(
            row.get("reason") == "already_covered_in_base_scan"
            for row in summary["decisions"]
        ))

    def test_dalfox_skips_urls_without_query_parameters(self):
        route = "https://app.example.test/profile"
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.agent_tool_router._exec") as execute:
            summary = run_agent_tool_requests(
                [{"agent": "xss", "tool_requests": [{"tool": "dalfox", "targets": [route]}]}],
                [route], td, scope={"assets": ["https://app.example.test"]},
            )
        execute.assert_not_called()
        self.assertEqual(summary["runs"], [])
        self.assertTrue(any(row["reason"] == "no_known_eligible_targets" for row in summary["decisions"]))


if __name__ == "__main__":
    unittest.main()
