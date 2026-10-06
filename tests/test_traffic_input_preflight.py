import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty import cli, orchestrator
from maher_bounty.traffic_ingest import ingest_traffic, TrafficInputError


class TrafficInputPreflightTests(unittest.TestCase):
    def test_missing_input_fails_before_recon_store_or_output_creation(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "results"
            with patch.object(orchestrator, "_collect_scope_inventory") as recon, patch.object(orchestrator, "ResearchStore") as store:
                with self.assertRaises(TrafficInputError):
                    orchestrator._run_loaded({"assets": ["https://example.test/"]}, {}, str(out),
                                             authorized=True, traffic_path=str(Path(td) / "missing.xml"))
                recon.assert_not_called()
                store.assert_not_called()
                self.assertFalse(out.exists())

    def test_cli_returns_two_without_traceback_or_recon(self):
        with tempfile.TemporaryDirectory() as td:
            errors = io.StringIO()
            with patch("sys.argv", ["maher-bounty", "auto-run", "--target", "https://example.test/", "--authorized", "--traffic", str(Path(td) / "missing.xml")]), contextlib.redirect_stderr(errors), patch.object(orchestrator, "_collect_scope_inventory") as recon:
                self.assertEqual(cli.main(), 2)
                recon.assert_not_called()
            self.assertIn("omit --traffic", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())

    def test_malformed_wrong_format_and_directory_fail_with_safe_diagnostics(self):
        with tempfile.TemporaryDirectory() as td:
            for name, value in [("bad.xml", "<items>fixture-secret"), ("wrong.xml", "<html/>"),
                                ("bad.har", "fixture-secret"), ("wrong.har", "{}"), ("array.har", "[]")]:
                path = Path(td) / name
                path.write_text(value)
                with self.subTest(name=name), self.assertRaises(TrafficInputError) as error:
                    ingest_traffic(path)
                self.assertNotIn("fixture-secret", str(error.exception))
            with self.assertRaises(TrafficInputError):
                ingest_traffic(td)

    def test_valid_empty_exports_remain_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            for name, content in [("empty.xml", "<items/>"), ("empty.har", json.dumps({"log": {"entries": []}}))]:
                path = Path(td) / name
                path.write_text(content)
                self.assertEqual(ingest_traffic(path), [])

    def test_burp_base64_must_be_valid_but_wrapped_whitespace_is_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            invalid = Path(td) / "invalid.xml"
            invalid.write_text('<items><item><request base64="true">%%%secret</request></item></items>')
            with self.assertRaises(TrafficInputError) as error:
                ingest_traffic(invalid)
            self.assertNotIn("secret", str(error.exception))

            wrapped = Path(td) / "wrapped.xml"
            wrapped.write_text('<items><item><url>https://example.test/</url><request base64="true">R0VUIC8gSFRUUC8xLjENCg==\n</request></item></items>')
            records = ingest_traffic(wrapped)
            self.assertEqual(len(records), 1)
            self.assertIn("GET / HTTP/1.1", records[0]["request_raw"])
