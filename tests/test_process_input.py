import subprocess
import sys
import unittest
from unittest.mock import patch

from maher_bounty.process_runtime import run


class ProcessInputTests(unittest.TestCase):
    def test_invalid_input_cannot_be_silently_dropped_by_writer_thread(self):
        cases = [(False, "text", TypeError), (True, b"bytes", TypeError),
                 (False, 42, TypeError), (True, "\ud800", UnicodeEncodeError)]
        for text, data, error in cases:
            with self.subTest(text=text, data=repr(data)), \
                    patch("threading.excepthook"), self.assertRaises(error):
                run([sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
                    input=data, capture_output=True, text=text, timeout=5)

    def test_binary_and_text_input_round_trip(self):
        for data, text, expected in [("snowman-\u2603", True, "snowman-\u2603"),
                                     (b"\x00\xff", False, b"\x00\xff"),
                                     (bytearray(b"bytearray"), False, b"bytearray"),
                                     (memoryview(b"memoryview"), False, b"memoryview")]:
            with self.subTest(data=repr(data)):
                result = run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                             input=data, capture_output=True, text=text, timeout=5)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.returncode, 0)

    def test_invalid_input_and_timeout_fail_before_launch(self):
        cases = [{"input": 42}, {"input": b"bytes", "text": True},
                 {"input": "\ud800", "text": True, "capture_output": True}]
        cases += [{"timeout": value} for value in [float("nan"), float("inf"), float("-inf"), True, "5"]]
        for options in cases:
            with self.subTest(options=repr(options)), patch("maher_bounty.process_runtime.subprocess.Popen") as launch:
                with self.assertRaises((TypeError, ValueError, UnicodeEncodeError)):
                    run([sys.executable, "-c", "pass"], **options)
                launch.assert_not_called()

    def test_nonpositive_timeout_remains_an_immediate_timeout(self):
        for timeout in [0, -1]:
            with self.subTest(timeout=timeout), self.assertRaises(subprocess.TimeoutExpired):
                run([sys.executable, "-c", "import time;time.sleep(60)"], capture_output=True, timeout=timeout)
