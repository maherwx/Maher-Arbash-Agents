import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from maher_bounty.continuous_service import ContinuousAnalysisService, ServiceConfig


def _har(url: str, status: int = 200) -> dict:
    return {
        "log": {"entries": [{
            "request": {"method": "GET", "url": url, "headers": []},
            "response": {"status": status, "headers": [], "content": {"text": "ok"}},
        }]}
    }


class ContinuousServiceSoakTests(unittest.TestCase):
    def _config(self, root: Path) -> ServiceConfig:
        return ServiceConfig(
            watch_dir=str(root / "incoming"),
            output_dir=str(root / "out"),
            db_path=str(root / "service.db"),
            research_db_path=str(root / "research.db"),
            poll_seconds=0.02,
            worker_count=2,
            retry_limit=2,
            retry_backoff_seconds=0.01,
            stale_running_seconds=0.0,
        )

    def _write_many(self, root: Path, count: int) -> None:
        incoming = root / "incoming"
        incoming.mkdir(exist_ok=True)
        for i in range(count):
            (incoming / f"{i:03d}.har").write_text(
                json.dumps(_har(f"https://example.test/item/{i}")),
                encoding="utf-8",
            )

    def test_multiple_jobs_complete_without_duplication(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_many(root, 12)
            service = ContinuousAnalysisService(self._config(root))
            thread = threading.Thread(target=service.run_forever, daemon=True)
            thread.start()
            try:
                deadline = time.time() + 10
                while time.time() < deadline:
                    status = service.status()
                    if status["jobs_by_status"].get("completed", 0) == 12:
                        break
                    time.sleep(0.05)
                status = service.status()
                self.assertEqual(status["jobs_total"], 12)
                self.assertEqual(status["jobs_by_status"].get("completed"), 12)
                self.assertEqual(status["jobs_by_status"].get("running", 0), 0)
                self.assertEqual(status["jobs_by_status"].get("queued", 0), 0)
                self.assertEqual(service.discover(), 0)
                self.assertEqual(service.status()["queue_depth"], 0)
            finally:
                service.stop_event.set()
                thread.join(timeout=2)
                service.close()

    def test_restart_recovers_interrupted_jobs_exactly_once(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_many(root, 5)
            config = self._config(root)

            first = ContinuousAnalysisService(config)
            try:
                first.discover()
                first._execute(
                    "UPDATE service_jobs SET status='running',updated_at=? WHERE id IN (1,2)",
                    (time.time() - 60,),
                )
            finally:
                first.close()

            second = ContinuousAnalysisService(config)
            thread = threading.Thread(target=second.run_forever, daemon=True)
            thread.start()
            try:
                deadline = time.time() + 10
                while time.time() < deadline:
                    status = second.status()
                    if status["jobs_by_status"].get("completed", 0) == 5:
                        break
                    time.sleep(0.05)
                status = second.status()
                self.assertEqual(status["jobs_total"], 5)
                self.assertEqual(status["jobs_by_status"].get("completed"), 5)
                rows = second.db.execute(
                    "SELECT id,attempts,status FROM service_jobs ORDER BY id"
                ).fetchall()
                self.assertEqual(len(rows), 5)
                self.assertTrue(all(status == "completed" for _,_,status in rows))
                self.assertTrue(all(attempts == 1 for _,attempts,_ in rows))
            finally:
                second.stop_event.set()
                thread.join(timeout=2)
                second.close()


if __name__ == "__main__":
    unittest.main()
