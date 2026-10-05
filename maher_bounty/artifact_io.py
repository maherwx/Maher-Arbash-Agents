"""Bounded atomic JSON replacement for local evidence artifacts."""
import json
import os
import tempfile
from pathlib import Path


def write_json_atomic(path, payload, *, max_bytes=8 * 1024 * 1024):
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("artifact byte limit must be a positive integer")
    data = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")
    if len(data) > max_bytes:
        raise ValueError("JSON artifact exceeds its byte limit")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
