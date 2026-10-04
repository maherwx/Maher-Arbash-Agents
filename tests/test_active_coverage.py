import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.active_testing import (
    _directory_discovery,
    _in_scope_unique,
    _tool_coverage,
)


class ActiveCoverageTests(unittest.TestCase):
    def test_discovered_urls_preserve_exact_in_scope_url_strings(self):
        exact = "https://example.test/a?next=%2Fadmin"
        urls = _in_scope_unique(
            [exact, exact, "https://outside.test/private"],
            {"assets": ["https://example.test/"], "out_of_scope": []},
        )
        self.assertEqual(urls, [exact])

    def test_content_discovery_skips_target_with_path_or_query(self):
        runs = []
        with tempfile.TemporaryDirectory() as td:
            _directory_discovery("https://example.test/shop?item=1", Path(td), runs)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "skipped")
        self.assertIn("origin URLs", runs[0]["reason"])

    @patch("maher_bounty.active_testing._exec")
    @patch("maher_bounty.active_testing.shutil.which", side_effect=lambda name: "/usr/bin/ffuf" if name == "ffuf" else None)
    def test_ffuf_discovery_is_rate_limited_and_uses_generated_wordlist(self, which, run):
        runs = []
        with tempfile.TemporaryDirectory() as td:
            host_dir = Path(td)
            _directory_discovery("https://example.test/", host_dir, runs)
            command = run.call_args.args[0]
            self.assertIn("-rate", command)
            self.assertEqual(command[command.index("-rate") + 1], "3")
            self.assertTrue((host_dir / "safe-content-paths.txt").is_file())
        self.assertEqual(len(runs), 1)

    @patch("maher_bounty.active_testing.shutil.which", return_value="/usr/bin/tool")
    def test_static_code_tools_are_reported_as_requiring_source(self, which):
        rows = _tool_coverage({"source_tree": True}, [])
        semgrep = next(row for row in rows if row["name"] == "Semgrep")
        self.assertEqual(semgrep["execution_status"], "requires_input")
        self.assertIn("source repository", semgrep["reason"])


if __name__ == "__main__":
    unittest.main()
