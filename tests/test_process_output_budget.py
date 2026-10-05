import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from maher_bounty.process_runtime import run, OutputLimitExceeded
from maher_bounty.active_testing import _exec, _tool_coverage
from maher_bounty.tool_orchestration import _run


class ProcessOutputBudgetTests(unittest.TestCase):
    def test_flood_stops_before_timeout_and_retains_bounded_partial_output(self):
        script = "import os,subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);\nwhile True: os.write(1,b'x'*65536)"
        started = time.monotonic()
        with self.assertRaises(OutputLimitExceeded) as failure:
            run([sys.executable, "-c", script], capture_output=True, timeout=20, max_output_bytes=100000)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(failure.exception.output), 100000)
        self.assertEqual(failure.exception.limit, 100000)

    def test_stdout_stderr_share_a_combined_budget(self):
        script = "import os; os.write(1,b'a'*40000);os.write(2,b'b'*40000)"
        with self.assertRaises(OutputLimitExceeded) as failure:
            run([sys.executable, "-c", script], capture_output=True, timeout=5, max_output_bytes=50000)
        self.assertEqual(len(failure.exception.output) + len(failure.exception.stderr), 50000)

    def test_invalid_utf8_does_not_crash_tool_or_hide_exit_status(self):
        result = run([sys.executable, "-c", "import os;os.write(1,b'\\xffok');raise SystemExit(3)"],
                     capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "\ufffdok")

    def test_file_stdout_remains_streamed_while_stderr_is_bounded(self):
        with tempfile.TemporaryFile() as output:
            result = run([sys.executable, "-c", "print('file-output');import sys;print('err',file=sys.stderr)"],
                         stdout=output, stderr=subprocess.PIPE, text=True, timeout=5, max_output_bytes=10)
            output.seek(0)
            self.assertIn(b"file-output", output.read())
        self.assertIsNone(result.stdout)
        self.assertEqual(result.stderr, "err\n")

    def test_adapters_report_output_limit_separately_from_timeout(self):
        failure = OutputLimitExceeded(["fixture"], 20, 50, output=b"partial", stderr=b"diagnostic")
        for module, function in [("maher_bounty.active_testing", _exec), ("maher_bounty.tool_orchestration", _run)]:
            with self.subTest(module=module), patch(module + ".shutil.which", return_value="fixture"), \
                    patch(module + ".run_process", side_effect=failure):
                self.assertEqual(function(["fixture"], timeout=1)["status"], "output_limit")
        with patch("maher_bounty.active_testing.recommend_tools", return_value={"tools": [{"command": "fixture"}]}):
            coverage = _tool_coverage({}, [{"tool": "fixture", "status": "output_limit"}])
        self.assertEqual(coverage[0]["execution_status"], "output_limited")

    def test_invalid_budget_fails_before_process_launch(self):
        for limit in [0, -1, True, "100"]:
            with self.subTest(limit=limit), patch("maher_bounty.process_runtime.subprocess.Popen") as launch, self.assertRaises(ValueError):
                run([sys.executable, "-c", "pass"], max_output_bytes=limit)
            launch.assert_not_called()
