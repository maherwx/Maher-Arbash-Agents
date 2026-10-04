import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from maher_bounty.continuous_service import ContinuousAnalysisService, ServiceConfig


class ContinuousServiceTests(unittest.TestCase):
    def _config(self, root: Path) -> ServiceConfig:
        return ServiceConfig(
            watch_dir=str(root / "incoming"),
            output_dir=str(root / "out"),
            db_path=str(root / "service.db"),
            research_db_path=str(root / "research.db"),
            poll_seconds=0.05,
            worker_count=1,
            retry_limit=1,
            stale_running_seconds=0.0,
        )

    def _write_har(self, root: Path) -> None:
        watch = root / "incoming"
        watch.mkdir(exist_ok=True)
        har = {
            "log": {"entries": [{
                "request": {"method": "GET", "url": "https://example.test/", "headers": []},
                "response": {"status": 200, "headers": [], "content": {"text": "ok"}},
            }]}
        }
        (watch / "one.har").write_text(json.dumps(har), encoding="utf-8")

    def test_discovery_deduplicates_and_tracks_jobs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_har(root)
            service = ContinuousAnalysisService(self._config(root))
            try:
                self.assertEqual(service.discover(), 1)
                self.assertEqual(service.discover(), 0)
                status = service.status()
                self.assertEqual(status["jobs_total"], 1)
                self.assertEqual(status["queue_depth"], 1)
                job = service._job(1)
                self.assertIsNotNone(job)
                service._process(job)
                status = service.status()
                self.assertEqual(status["jobs_by_status"].get("completed"), 1)
                self.assertEqual(service.discover(), 0)
                self.assertTrue((root / "out" / "job-00000001" / "service-summary.json").exists())
            finally:
                service.close()

    def test_recovers_interrupted_running_job_after_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_har(root)
            config = self._config(root)

            first = ContinuousAnalysisService(config)
            try:
                self.assertEqual(first.discover(), 1)
                first._execute(
                    "UPDATE service_jobs SET status='running',updated_at=? WHERE id=1",
                    (time.time() - 60,),
                )
            finally:
                first.close()

            second = ContinuousAnalysisService(config)
            try:
                recovered = second._job(1)
                self.assertIsNotNone(recovered)
                self.assertEqual(recovered["status"], "queued")
                self.assertEqual(second.status()["queue_depth"], 1)
                second._process(recovered)
                self.assertEqual(second.status()["jobs_by_status"].get("completed"), 1)
            finally:
                second.close()


if __name__ == "__main__":
    unittest.main()
