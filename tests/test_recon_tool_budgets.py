import subprocess
import unittest
from unittest.mock import patch

from maher_bounty.tool_orchestration import _run


class ReconToolBudgetTests(unittest.TestCase):
    @patch("maher_bounty.tool_orchestration.shutil.which", return_value="/usr/bin/httpx")
    @patch("maher_bounty.tool_orchestration.subprocess.run")
    def test_recon_tools_receive_three_minute_extension(self, run, which):
        run.return_value = subprocess.CompletedProcess(args=["httpx"], returncode=0, stdout="", stderr="")
        result = _run(["httpx", "example.test"], timeout=25)
        self.assertEqual(run.call_args.kwargs["timeout"], 205)
        self.assertEqual(result["timeout_seconds"], 205)


if __name__ == "__main__":
    unittest.main()
