import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.active_testing import run_active_testing


class ActiveTestingScopeTests(unittest.TestCase):
    def test_crawler_uses_exact_fqdn_and_parameter_scan_is_allowlisted(self):
        commands = []

        def fake_exec(cmd, *, timeout, output=None):
            commands.append(cmd)
            return {"tool": cmd[0], "status": "missing", "command": cmd}

        inventory = {
            "endpoints": [
                {"value": "https://app.example.test/login"},
                {"value": "https://api.example.test/secret"},
                {"value": "https://evil.test/"},
            ]
        }
        scope = {"assets": ["app.example.test"], "out_of_scope": []}
        with tempfile.TemporaryDirectory() as temp, patch("maher_bounty.active_testing._exec", side_effect=fake_exec):
            result = run_active_testing("https://app.example.test", inventory, temp, scope=scope)
            target_lines = (Path(temp) / "targets.txt").read_text(encoding="utf-8").splitlines()

        katana = next(cmd for cmd in commands if cmd[0] == "katana")
        self.assertIn("-fs", katana)
        self.assertEqual(katana[katana.index("-fs") + 1], "fqdn")
        self.assertEqual(target_lines, ["https://app.example.test", "https://app.example.test/login"])
        self.assertEqual(result["scope_review"]["rejected_url_count"], 2)

    def test_active_checks_deduplicate_same_origin_and_skip_exclusions(self):
        commands = []

        def fake_exec(cmd, *, timeout, output=None):
            commands.append(cmd)
            return {"tool": cmd[0], "status": "missing", "command": cmd}

        inventory = {
            "hosts": [
                {"value": "app.example.test"},
                {"value": "api.example.test"},
                {"value": "admin.example.test"},
            ],
            "endpoints": [
                {"value": "https://app.example.test/login"},
                {"value": "https://api.example.test/v1"},
                {"value": "https://admin.example.test/"},
            ],
        }
        scope = {"assets": ["*.example.test"], "out_of_scope": ["admin.example.test"]}
        with tempfile.TemporaryDirectory() as temp, patch("maher_bounty.active_testing._exec", side_effect=fake_exec):
            result = run_active_testing("example.test", inventory, temp, scope=scope)
            nuclei_runs = [cmd for cmd in commands if cmd[0] == "nuclei"]
            self.assertEqual(len(nuclei_runs), 1)
            self.assertEqual(nuclei_runs[0][nuclei_runs[0].index("-l") + 1], str(Path(temp) / "targets.txt"))

        self.assertEqual(result["targets"], [
            "https://app.example.test",
            "https://api.example.test",
            "https://app.example.test/login",
            "https://api.example.test/v1",
        ])
        katana_targets = [cmd[cmd.index("-u") + 1] for cmd in commands if cmd[0] == "katana"]
        self.assertEqual(katana_targets, ["https://app.example.test", "https://api.example.test"])
        self.assertIn("https://app.example.test/login", result["discovered_in_scope_urls"])
        self.assertIn("https://api.example.test/v1", result["discovered_in_scope_urls"])
        self.assertEqual(result["scope_review"]["rejected_url_count"], 3)
        self.assertIn("https://admin.example.test/", result["scope_review"]["rejected_urls"])


if __name__ == "__main__":
    unittest.main()
