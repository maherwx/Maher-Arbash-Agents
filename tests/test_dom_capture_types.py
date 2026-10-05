import unittest
from maher_bounty.browser_runtime import _capture_value
from maher_bounty.workflow_execution import _validate_browser_settings


class DomCaptureTypeTests(unittest.TestCase):
    def test_strict_bounded_numeric_text(self):
        for text, expected in [("10", 10), (" -3.5 ", -3.5), ("1e2", 100), ("0", 0)]:
            self.assertEqual(_capture_value(text, {"type": "number"}), expected)
        for text in [None, "", "USD 10", "10,000", "true", '"10"', "null", "[]", "{}", "NaN", "Infinity", "1e309", "1" * 129]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                _capture_value(text, {"type": "number"})

    def test_default_text_capture_remains_unchanged(self):
        self.assertEqual(_capture_value(" 0010 ", {}), " 0010 ")

    def test_capture_type_preflight(self):
        for value in ["integer", None, True, [], {}]:
            with self.assertRaises(ValueError):
                _validate_browser_settings({"capture_dom": {"n": {"selector": "#n", "type": value}}})
        _validate_browser_settings({"capture_dom": {"n": {"selector": "#n", "type": "number"}}})
