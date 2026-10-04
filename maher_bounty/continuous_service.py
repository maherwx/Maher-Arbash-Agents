from __future__ import annotations

import json
import signal
import sqlite3
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from queue import Queue, Empty

from .traffic_pipeline import analyze_traffic


SCHEMA = """
CREATE TABLE IF NOT EXISTS service_jobs(
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_error TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_jobs_path_kind ON service_jobs(path,kind);
CREATE TABLE IF NOT EXISTS service_state(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(slots=True)
class ServiceConfig:
    watch_dir: str = "incoming"
    output_dir: str = "results/continuous"
    db_path: str = ".maher/service.db"
    research_db_path: str = ".maher/research.db"
    poll_seconds: float = 2.0
    worker_count: int = 2
    retry_limit: int = 3
    retry_backoff_seconds: float = 5.0
    stale_running_seconds: float = 30.0

    def as_dict(self) -> dict:
        return asdict(self)


class ContinuousAnalysisService:
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.watch_dir = Path(config.watch_dir)
        self.output_dir = Path(config.output_dir)
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        db_path = Path(config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.lock = threading.RLock()
        self.queue: Queue[int] = Queue()
        self.enqueued: set[int] = set()
        self.stop_event = threading.Event()
        self.workers: list[threading.Thread] = []
        self.recover_incomplete_jobs()

    def _execute(self, sql: str, params=()):
        with self.lock:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur

    def _enqueue(self, job_id: int) -> bool:
        with self.lock:
            if job_id in self.enqueued:
                return False
            self.enqueued.add(job_id)
            self.queue.put(job_id)
            return True

    def recover_incomplete_jobs(self) -> int:
        now = time.time()
        cutoff = now - max(0.0, self.config.stale_running_seconds)
        recovered = 0
        with self.lock:
            rows = self.db.execute(
                "SELECT id,status,updated_at FROM service_jobs WHERE status IN ('queued','running')"
            ).fetchall()
            for job_id, status, updated_at in rows:
                if status == "running" and float(updated_at or 0) > cutoff:
                    continue
                if status == "running":
                    self.db.execute(
                        "UPDATE service_jobs SET status='queued',updated_at=?,last_error=? WHERE id=?",
                        (now, "recovered after interrupted service execution", job_id),
                    )
                if self._enqueue(int(job_id)):
                    recovered += 1
            self.db.commit()
        return recovered

    def _discover_kind(self, path: Path) -> str | None:
        suffix = path.suffix.lower()
        if suffix == ".har":
            return "har"
        if suffix == ".xml":
            return "burp"
        return None

    def discover(self) -> int:
        queued = 0
        for path in self.watch_dir.rglob("*"):
            if not path.is_file():
                continue
            kind = self._discover_kind(path)
            if not kind:
                continue
            now = time.time()
            with self.lock:
                row = self.db.execute(
                    "SELECT id,status FROM service_jobs WHERE path=? AND kind=?",
                    (str(path), kind),
                ).fetchone()
                if row is None:
                    cur = self.db.execute(
                        "INSERT INTO service_jobs(path,kind,status,attempts,first_seen,updated_at) VALUES(?,?,?,?,?,?)",
                        (str(path), kind, "queued", 0, now, now),
                    )
                    job_id = int(cur.lastrowid)
                    self.db.commit()
                    if self._enqueue(job_id):
                        queued += 1
                elif row[1] in {"failed", "queued"}:
                    if self._enqueue(int(row[0])):
                        queued += 1
        return queued

    def _job(self, job_id: int) -> dict | None:
        with self.lock:
            row = self.db.execute(
                "SELECT id,path,kind,status,attempts FROM service_jobs WHERE id=?", (job_id,)
            ).fetchone()
        if not row:
            return None
        return {"id": row[0], "path": row[1], "kind": row[2], "status": row[3], "attempts": row[4]}

    def _process(self, job: dict) -> None:
        job_id = job["id"]
        attempts = int(job["attempts"]) + 1
        now = time.time()
        self._execute(
            "UPDATE service_jobs SET status=?,attempts=?,updated_at=?,last_error=NULL WHERE id=?",
            ("running", attempts, now, job_id),
        )
        target_out = self.output_dir / f"job-{job_id:08d}"
        try:
            result = analyze_traffic(
                job["path"],
                kind=job["kind"],
                out_dir=target_out,
                db_path=self.config.research_db_path,
            )
            summary = {
                "job_id": job_id,
                "source": job["path"],
                "kind": job["kind"],
                "run_id": result.get("run_id"),
                "record_count": result.get("record_count"),
                "anomaly_count": result.get("anomalies", {}).get("anomaly_count", 0),
                "protocol_signal_count": result.get("protocols", {}).get("signal_count", 0),
                "workflow_divergence_count": result.get("workflow_divergences", {}).get("divergence_count", 0),
                "provenance_chain_count": result.get("provenance", {}).get("chain_count", 0),
                "priority_target_count": result.get("priorities", {}).get("target_count", 0),
            }
            target_out.mkdir(parents=True, exist_ok=True)
            (target_out / "service-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            self._execute(
                "UPDATE service_jobs SET status=?,updated_at=?,last_error=NULL WHERE id=?",
                ("completed", time.time(), job_id),
            )
        except Exception as exc:
            state = "failed" if attempts >= self.config.retry_limit else "queued"
            self._execute(
                "UPDATE service_jobs SET status=?,updated_at=?,last_error=? WHERE id=?",
                (state, time.time(), repr(exc)[:2000], job_id),
            )
            if state == "queued" and not self.stop_event.wait(self.config.retry_backoff_seconds * attempts):
                self._enqueue(job_id)

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                job_id = self.queue.get(timeout=0.5)
            except Empty:
                continue
            with self.lock:
                self.enqueued.discard(job_id)
            try:
                job = self._job(job_id)
                if job and job["status"] in {"queued", "failed"}:
                    self._process(job)
            finally:
                self.queue.task_done()

    def status(self) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT status,COUNT(*) FROM service_jobs GROUP BY status").fetchall()
            total = self.db.execute("SELECT COUNT(*) FROM service_jobs").fetchone()[0]
            heartbeat = self.db.execute("SELECT value FROM service_state WHERE key='heartbeat'").fetchone()
        return {
            "running": not self.stop_event.is_set(),
            "watch_dir": str(self.watch_dir),
            "output_dir": str(self.output_dir),
            "workers": len(self.workers),
            "jobs_total": total,
            "jobs_by_status": {status: count for status, count in rows},
            "queue_depth": self.queue.qsize(),
            "heartbeat": float(heartbeat[0]) if heartbeat else None,
        }

    def run_forever(self) -> None:
        self.stop_event.clear()
        self.recover_incomplete_jobs()
        for idx in range(max(1, self.config.worker_count)):
            t = threading.Thread(target=self._worker, name=f"maher-worker-{idx+1}", daemon=True)
            t.start()
            self.workers.append(t)

        def stop_handler(signum, frame):
            self.stop_event.set()

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, stop_handler)
            signal.signal(signal.SIGINT, stop_handler)

        try:
            while not self.stop_event.is_set():
                self.discover()
                self._execute(
                    "INSERT INTO service_state(key,value) VALUES('heartbeat',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(time.time()),),
                )
                self.stop_event.wait(self.config.poll_seconds)
        finally:
            self.stop_event.set()
            for t in self.workers:
                t.join(timeout=2.0)

    def close(self) -> None:
        self.stop_event.set()
        with self.lock:
            self.db.close()


def write_status(config: ServiceConfig) -> dict:
    service = ContinuousAnalysisService(config)
    try:
        return service.status()
    finally:
        service.close()
