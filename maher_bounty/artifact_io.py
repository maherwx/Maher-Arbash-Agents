"""Bounded atomic JSON replacement for local evidence artifacts."""
import json
import os
import tempfile
from pathlib import Path


def write_json_atomic(path, payload, *, max_bytes=8 * 1024 * 1024):
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("artifact byte limit must be a positive integer")
    # Stop encoding once the artifact budget is exceeded instead of building
    # a complete oversized JSON string and a second UTF-8 copy first.
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False)
    data = bytearray()
    for chunk in encoder.iterencode(payload):
        # Encoding slices also bounds transient UTF-8 allocations for a large
        # string token. The encoder's token and input object are not budgeted.
        for offset in range(0, len(chunk), 16384):
            encoded = chunk[offset:offset + 16384].encode("utf-8")
            if len(encoded) > max_bytes - len(data):
                raise ValueError("JSON artifact exceeds its byte limit")
            data.extend(encoded)
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
