from __future__ import annotations

import hashlib
import json


def result_fingerprint(summary: dict) -> str:
    """Stable semantic fingerprint excluding paths/timing and other runtime noise."""
    normalized=[]
    for row in summary.get("results", []):
        normalized.append({
            "name": row.get("name"),
            "passed": bool(row.get("passed")),
            "checks": row.get("checks", {}),
            "classification": row.get("classification", {}),
            "observed": row.get("observed", {}),
        })
    payload=json.dumps(normalized,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    return hashlib.sha256(payload).hexdigest()


def regression_summary(first: dict, second: dict) -> dict:
    a=result_fingerprint(first); b=result_fingerprint(second)
    return {"stable":a==b,"first_fingerprint":a,"second_fingerprint":b,"case_count":len(first.get("results",[]))}
