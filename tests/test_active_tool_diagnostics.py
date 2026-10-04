import subprocess
import unittest
from unittest.mock import patch

from maher_bounty.active_testing import _exec


class ActiveToolDiagnosticsTests(unittest.TestCase):
    @patch("maher_bounty.active_testing.shutil.which", return_value="/usr/bin/nuclei")
    @patch("maher_bounty.active_testing.subprocess.run")
    def test_nonzero_exit_preserves_stderr_and_exit_code(self, run, which):
        run.return_value = subprocess.CompletedProcess(
            args=["nuclei"], returncode=2, stdout="", stderr="no templates found"
        )
        result = _exec(["nuclei", "-u", "https://example.test/"], timeout=2)
        self.assertEqual(result["status"], "nonzero")
        self.assertEqual(result["returncode"], 2)
        self.assertIn("no templates found", result["stderr_tail"])

    @patch("maher_bounty.active_testing.shutil.which", return_value="/usr/bin/nuclei")
    @patch("maher_bounty.active_testing.subprocess.run", side_effect=subprocess.TimeoutExpired("nuclei", 1, stderr=b"network stalled"))
    def test_timeout_preserves_stderr(self, run, which):
        result = _exec(["nuclei", "-u", "https://example.test/"], timeout=1)
        self.assertEqual(result["status"], "timeout")
        self.assertIn("network stalled", result["stderr_tail"])


if __name__ == "__main__":
    unittest.main()
