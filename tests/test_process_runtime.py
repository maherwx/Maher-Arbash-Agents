import os
import subprocess
import sys
import time
import unittest

from maher_bounty.process_runtime import run


class ProcessRuntimeTests(unittest.TestCase):
    def test_captures_output_input_and_nonzero_returncode(self):
        result = run([sys.executable, "-c", "import sys; print(sys.stdin.read()); print('diagnostic',file=sys.stderr); sys.exit(3)"],
                     input="fixture-input", capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 3)
        self.assertIn("fixture-input", result.stdout)
        self.assertIn("diagnostic", result.stderr)

    def test_timeout_kills_descendants_holding_pipe_handles(self):
        script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print('partial-evidence',flush=True); time.sleep(60)"
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as failure:
            run([sys.executable, "-c", script], capture_output=True, text=True, timeout=1)
        self.assertLess(time.monotonic() - started, 9)
        self.assertIn("partial-evidence", str(failure.exception.output))

    def test_exited_parent_with_live_descendant_does_not_hang_cleanup(self):
        script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print('parent-exited',flush=True)"
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run([sys.executable, "-c", script], capture_output=True, text=True, timeout=0.5)
        self.assertLess(time.monotonic() - started, 4)

    def test_successful_exit_and_check(self):
        self.assertEqual(run([sys.executable, "-c", "pass"], timeout=5).returncode, 0)
        with self.assertRaises(subprocess.CalledProcessError):
            run([sys.executable, "-c", "raise SystemExit(4)"], check=True, timeout=5)
