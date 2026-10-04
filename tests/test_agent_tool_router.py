import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.agent_tool_router import run_agent_tool_requests


class AgentToolRouterTests(unittest.TestCase):
    def test_only_allowlisted_tools_and_known_in_scope_urls_run(self):
        safe = "https://app.example.test/search?q=one"
        outside = "https://attacker.example/path"
        results = [
            {"agent": "xss_reviewer", "tool_requests": [
                {"tool": "dalfox", "targets": [safe, outside], "reason": "query parameter observed"},
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
