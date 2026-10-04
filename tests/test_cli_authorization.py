import sys
import unittest
from unittest.mock import patch

from maher_bounty.cli import main


class RunAuthorizationFlagTests(unittest.TestCase):
    @patch("maher_bounty.cli.run", return_value={
        "agent_count": 0,
        "active_testing": {"status": "skipped", "findings": []},
    })
    @patch.object(sys, "argv", ["maher-bounty", "run", "--scope", "scope.yaml", "--rules", "rules.yaml", "--authorized"])
    def test_run_exposes_and_passes_authorized_flag(self, run):
        main()
        run.assert_called_once_with("scope.yaml", "rules.yaml", "reports", None, authorized=True)


if __name__ == "__main__":
    unittest.main()
