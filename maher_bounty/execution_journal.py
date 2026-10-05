"""Local scope-bound checkpoints for completed tool execution rounds."""
import hashlib
import json
import os
import tempfile
from pathlib import Path


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("execution journal contains duplicate JSON fields")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("execution journal contains non-finite JSON values")


class ExecutionJournal:
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, path, binding):
        self.path = Path(path)
        self.binding = hashlib.sha256(_canonical(binding)).hexdigest()
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
        if not self.path.is_file():
            raise ValueError("execution resume requires an existing bounded journal")
        # Bound the read itself, not only a stat before a potentially growing file.
        with self.path.open("rb") as stream:
            data = stream.read(self.MAX_BYTES + 1)
        if len(data) > self.MAX_BYTES:
            raise ValueError("execution journal exceeds its size limit")
        state = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields,
                           parse_constant=_invalid_constant)
        if not isinstance(state, dict) or state.get("version") != 2 or state.get("binding") != self.binding:
            raise ValueError("execution journal does not match the supplied scope and execution context")
        expected = {key: state.get(key) for key in ("version", "binding", "phase", "payload")}
        if state.get("checksum") != hashlib.sha256(_canonical(expected)).hexdigest():
            raise ValueError("execution journal integrity check failed")
        if state.get("phase") != "completed_round":
            raise ValueError("interrupted tool round has uncertain effects; automatic replay is blocked")
        payload = state.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("execution journal payload is invalid")
        return payload

    def save(self, phase, payload):
        if phase not in {"running_round", "completed_round"} or not isinstance(payload, dict):
            raise ValueError("execution journal requires a valid phase and object payload")
        state = {"version": 2, "binding": self.binding, "phase": phase, "payload": payload}
        state["checksum"] = hashlib.sha256(_canonical(state)).hexdigest()
        data = _canonical(state)
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
