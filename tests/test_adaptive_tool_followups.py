import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.agent_tool_router import run_agent_tool_requests


class AdaptiveToolFollowupTests(unittest.TestCase):
    def test_reuses_base_coverage_and_scans_only_new_scoped_crawl_urls(self):
        target = "https://app.example.test/"
        new_route = "https://app.example.test/new?item=1"
        outside = "https://outside.example/new"
        scope = {"assets": [target], "out_of_scope": []}
        with tempfile.TemporaryDirectory() as td:
            base_targets = Path(td) / "base-targets.txt"
            base_targets.write_text(target + "\n", encoding="utf-8")
            active = {
                "runs": [{
                    "tool": "nuclei", "status": "ok",
                    "command": ["nuclei", "-l", str(base_targets)],
                }],
            }

            def fake_exec(command, **kwargs):
                if command[0] == "hakrawler":
                    self.assertEqual(kwargs.get("input_text"), target + "\n")
                    kwargs["output"].write_text(new_route + "\n" + outside + "\n", encoding="utf-8")
                return {"tool": command[0], "status": "ok", "command": command}

            with patch("maher_bounty.agent_tool_router.shutil.which", return_value="/usr/bin/tool"), \
                 patch("maher_bounty.agent_tool_router._exec", side_effect=fake_exec) as execute:
                summary = run_agent_tool_requests(
                    [{
                        "agent": "route_reviewer",
                        "tool_requests": [
                            {"tool": "nuclei", "targets": [target]},
                            {"tool": "hakrawler", "targets": [target]},
                        ],
                    }],
                    [target], Path(td) / "followups", scope=scope, active_testing=active,
                )

            commands = [call.args[0] for call in execute.call_args_list]
            nuclei_calls = [command for command in commands if command[0] == "nuclei"]
            self.assertEqual(len(nuclei_calls), 1)
            self.assertEqual(commands[0][0], "hakrawler")
            followup_targets = Path(nuclei_calls[0][2]).read_text(encoding="utf-8").splitlines()
            self.assertEqual(followup_targets, [new_route])
            self.assertEqual(summary["new_in_scope_urls"], [new_route])
            self.assertNotIn(outside, summary["new_in_scope_urls"])
            self.assertTrue(any(
                row.get("reason") == "already_covered_in_base_scan"
                for row in summary["decisions"]
            ))


if __name__ == "__main__":
    unittest.main()
