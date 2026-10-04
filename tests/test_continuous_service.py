import json
import tempfile
import unittest
from pathlib import Path

from maher_bounty.continuous_service import ContinuousAnalysisService, ServiceConfig


class ContinuousServiceTests(unittest.TestCase):
    def test_discovery_deduplicates_and_tracks_jobs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            watch = root / "incoming"
            out = root / "out"
            watch.mkdir()
            har = {
                "log": {"entries": [{
                    "request": {"method": "GET", "url": "https://example.test/", "headers": []},
                    "response": {"status": 200, "headers": [], "content": {"text": "ok"}},
                }]}
            }
            (watch / "one.har").write_text(json.dumps(har), encoding="utf-8")
            config = ServiceConfig(
                watch_dir=str(watch),
                output_dir=str(out),
                db_path=str(root / "service.db"),
                research_db_path=str(root / "research.db"),
                poll_seconds=0.05,
                worker_count=1,
                retry_limit=1,
            )
            service = ContinuousAnalysisService(config)
            try:
                self.assertEqual(service.discover(), 1)
                self.assertEqual(service.discover(), 1)
                status = service.status()
                self.assertEqual(status["jobs_total"], 1)
                self.assertGreaterEqual(status["queue_depth"], 1)
                job = service._job(1)
                self.assertIsNotNone(job)
                service._process(job)
                status = service.status()
                self.assertEqual(status["jobs_by_status"].get("completed"), 1)
                self.assertEqual(service.discover(), 0)
                self.assertTrue((out / "job-00000001" / "service-summary.json").exists())
            finally:
                service.close()


if __name__ == "__main__":
    unittest.main()
