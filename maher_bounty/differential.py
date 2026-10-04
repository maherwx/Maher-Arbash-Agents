from __future__ import annotations

import hashlib
import json
from difflib import SequenceMatcher

VOLATILE_HEADERS = {"date", "server-timing", "x-request-id", "traceparent", "cf-ray"}


def _body_text(response: dict) -> str:
    body = response.get("body", "")
    if isinstance(body, (dict, list)):
        return json.dumps(body, sort_keys=True, ensure_ascii=False)
    return str(body)


def compare_responses(baseline: dict, candidate: dict) -> dict:
    """Compare captured responses semantically without issuing network requests."""
    a, b = _body_text(baseline), _body_text(candidate)
    ah = {str(k).lower(): str(v) for k, v in (baseline.get("headers") or {}).items() if str(k).lower() not in VOLATILE_HEADERS}
    bh = {str(k).lower(): str(v) for k, v in (candidate.get("headers") or {}).items() if str(k).lower() not in VOLATILE_HEADERS}
    changed_headers = sorted(k for k in set(ah) | set(bh) if ah.get(k) != bh.get(k))
    similarity = SequenceMatcher(None, a[:200000], b[:200000]).ratio()
    return {
        "status_changed": baseline.get("status") != candidate.get("status"),
        "baseline_status": baseline.get("status"),
        "candidate_status": candidate.get("status"),
        "body_similarity": round(similarity, 5),
        "body_length_delta": len(b) - len(a),
        "changed_headers": changed_headers[:100],
        "baseline_body_sha256": hashlib.sha256(a.encode("utf-8", errors="ignore")).hexdigest(),
        "candidate_body_sha256": hashlib.sha256(b.encode("utf-8", errors="ignore")).hexdigest(),
        "material_difference": bool(baseline.get("status") != candidate.get("status") or similarity < 0.92 or changed_headers),
    }
