"""Local scope-bound checkpoints for completed tool execution rounds."""
import hashlib
import json
import os
import tempfile
from pathlib import Path


class ExecutionJournal:
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, path, binding):
        self.path = Path(path)
        encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.binding = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ValueError("execution journal is locked; inspect the prior process before recovery") from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(str(os.getpid()))
        except BaseException:
            self.lock_path.unlink(missing_ok=True)
            raise
        return self

    def __exit__(self, *args):
        self.lock_path.unlink(missing_ok=True)

    def load(self):
        if not self.path.is_file() or self.path.stat().st_size > self.MAX_BYTES:
            raise ValueError("execution resume requires an existing bounded journal")
        state = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("version") != 1 or state.get("binding") != self.binding:
            raise ValueError("execution journal does not match the supplied scope and execution context")
        if state.get("phase") != "completed_round":
            raise ValueError("interrupted tool round has uncertain effects; automatic replay is blocked")
        payload = state.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("execution journal payload is invalid")
        return payload

    def save(self, phase, payload):
        data = json.dumps({"version": 1, "binding": self.binding, "phase": phase,
                           "payload": payload}, ensure_ascii=False).encode("utf-8")
        if len(data) > self.MAX_BYTES:
            raise ValueError("execution journal exceeds its size limit")
        descriptor, name = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
