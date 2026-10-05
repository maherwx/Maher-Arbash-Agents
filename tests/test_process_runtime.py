import os
import subprocess
import sys
import time
import unittest
import tempfile
from pathlib import Path

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

    def test_completed_parent_cleans_up_children_without_inherited_pipes(self):
        # Child confirms startup before parent exits, then would write a
        # delayed marker if invocation cleanup leaves it running.
        with tempfile.TemporaryDirectory() as td:
            for code, check in [(0, False), (4, False), (4, True)]:
                with self.subTest(code=code, check=check):
                    ready = Path(td) / f"ready-{code}-{check}"
                    leaked = Path(td) / f"leaked-{code}-{check}"
                    child = "import sys,time; from pathlib import Path; Path(sys.argv[1]).touch(); time.sleep(1); Path(sys.argv[2]).touch()"
                    parent = "import subprocess,sys,time; from pathlib import Path; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); deadline=time.monotonic()+3\nwhile not Path(sys.argv[2]).exists() and time.monotonic()<deadline: time.sleep(.01)\nsys.exit(int(sys.argv[4]))"
                    command = [sys.executable, "-c", parent, child, str(ready), str(leaked), str(code)]
                    if check:
                        with self.assertRaises(subprocess.CalledProcessError):
                            run(command, capture_output=True, timeout=5, check=True)
                    else:
                        self.assertEqual(run(command, capture_output=True, timeout=5).returncode, code)
                    self.assertTrue(ready.exists(), "child must start for regression to be meaningful")
                    time.sleep(1.2)
                    self.assertFalse(leaked.exists(), "completed tool left a child process running")
