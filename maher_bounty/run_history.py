from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class RunHistory:
    def __init__(self, db_path: str | Path = ".maher/research.db"):
        self.path = Path(db_path)

    def _connect(self):
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        return sqlite3.connect(self.path)

    def list_runs(self, limit: int = 20) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,created_at,scope,status FROM runs ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        out = []
        for run_id, created_at, scope, status in rows:
            try:
                scope_obj = json.loads(scope)
            except Exception:
                scope_obj = {}
            out.append({"id": run_id, "created_at": created_at, "status": status, "scope": scope_obj})
        return out

    def load_run(self, run_id: int) -> dict:
        with self._connect() as db:
            run = db.execute("SELECT id,created_at,scope,status FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise KeyError(run_id)
            checkpoints = db.execute(
                "SELECT stage,payload,updated_at FROM checkpoints WHERE run_id=? ORDER BY updated_at",
                (run_id,),
            ).fetchall()
            evidence = db.execute(
                "SELECT source,kind,payload,created_at FROM evidence WHERE run_id=? ORDER BY id",
                (run_id,),
            ).fetchall()
            findings = db.execute(
                "SELECT fingerprint,status,confidence,payload FROM findings WHERE run_id=? ORDER BY id",
                (run_id,),
            ).fetchall()

        def loads(value):
            try:
                return json.loads(value)
            except Exception:
                return value

        return {
            "run": {"id": run[0], "created_at": run[1], "scope": loads(run[2]), "status": run[3]},
            "checkpoints": [
                {"stage": stage, "payload": loads(payload), "updated_at": updated}
                for stage, payload, updated in checkpoints
            ],
            "evidence": [
                {"source": source, "kind": kind, "payload": loads(payload), "created_at": created}
                for source, kind, payload, created in evidence
            ],
            "findings": [
                {"fingerprint": fp, "status": status, "confidence": confidence, "payload": loads(payload)}
                for fp, status, confidence, payload in findings
            ],
        }

    def resumable_checkpoint(self, run_id: int) -> dict | None:
        data = self.load_run(run_id)
        checkpoints = data["checkpoints"]
        return checkpoints[-1] if checkpoints else None

    def export_run(self, run_id: int, output: str | Path) -> Path:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.load_run(run_id), ensure_ascii=False, indent=2), encoding="utf-8")
        return out
