from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (run_id INTEGER NOT NULL, stage TEXT NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(run_id, stage));
CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, source TEXT, kind TEXT, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, fingerprint TEXT, status TEXT, confidence INTEGER, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""

class ResearchStore:
    def __init__(self, path=".maher/research.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)
        self.db.commit()

    def create_run(self, scope: dict) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cur = self.db.execute("INSERT INTO runs(created_at,scope,status) VALUES(?,?,?)", (now, json.dumps(scope, ensure_ascii=False), "running"))
        self.db.commit()
        return int(cur.lastrowid)

    def checkpoint(self, run_id: int, stage: str, payload):
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute("INSERT INTO checkpoints(run_id,stage,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(run_id,stage) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at", (run_id, stage, json.dumps(payload, ensure_ascii=False), now))
        self.db.commit()

    def add_evidence(self, run_id: int, source: str, kind: str, payload):
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute("INSERT INTO evidence(run_id,source,kind,payload,created_at) VALUES(?,?,?,?,?)", (run_id, source, kind, json.dumps(payload, ensure_ascii=False), now))
        self.db.commit()

    def save_findings(self, run_id: int, findings: list[dict]):
        for item in findings:
            fp = f"{item.get('title','').lower()}|{item.get('target','').lower()}"
            self.db.execute("INSERT INTO findings(run_id,fingerprint,status,confidence,payload) VALUES(?,?,?,?,?)", (run_id, fp, item.get("status"), item.get("confidence_score", 0), json.dumps(item, ensure_ascii=False)))
        self.db.commit()

    def finish(self, run_id: int, status="completed"):
        self.db.execute("UPDATE runs SET status=? WHERE id=?", (status, run_id))
        self.db.commit()
