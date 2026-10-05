import tempfile
import unittest
from collections import Counter
from unittest.mock import patch

from maher_bounty.active_testing import run_active_testing


class ActiveScanDeduplicationTests(unittest.TestCase):
    def test_same_origin_routes_are_not_scanned_with_same_tools_repeatedly(self):
        target = "https://app.example.test/"
        inventory = {
            "hosts": [{"value": "app.example.test"}],
            "endpoints": [
                {"value": "https://app.example.test/login"},
                {"value": "https://app.example.test/api/status"},
            ],
            "http": [],
        }
        scope = {
            "assets": [target, "https://app.example.test/login", "https://app.example.test/api/status"],
            "out_of_scope": [],
        }
        with tempfile.TemporaryDirectory() as td, \
             patch("maher_bounty.active_testing.shutil.which", return_value="/usr/bin/tool"), \
             patch("maher_bounty.active_testing._exec", side_effect=lambda cmd, **kwargs: {
                 "tool": cmd[0], "status": "ok", "command": cmd
             }) as execute, \
             patch("maher_bounty.active_testing._directory_discovery", return_value=[]):
            result = run_active_testing(target, inventory, td, scope=scope)

        executed = [call.args[0] for call in execute.call_args_list]
        counts = Counter(command[0] for command in executed)
        self.assertEqual(counts["katana"], 1)
        self.assertEqual(counts["nikto"], 1)
        self.assertEqual(counts["nmap"], 1)
        self.assertEqual(counts["tlsx"], 1)
        tls_cmd = next(command for command in executed if command[0] == "tlsx")
        self.assertIn("-json", tls_cmd)
        self.assertNotIn("-san", tls_cmd)
        self.assertNotIn("-cn", tls_cmd)
        skipped = [row for row in result["runs"] if row.get("status") == "skipped"]
        self.assertTrue(any(row.get("reason") == "already executed for this origin in the current run" for row in skipped))


if __name__ == "__main__":
    unittest.main()
