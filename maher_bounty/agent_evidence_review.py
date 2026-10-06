"""Review recorded tool evidence without issuing validation requests."""
import hashlib
import re
from collections import Counter

from .burp_evidence import _safe_url
from .scope_policy import is_in_scope_url


def _browser_proof_bound(finding, runs, known):
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("control_passed") is not True:
        return False
    proofs = evidence.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 2 or any(not isinstance(proof, dict) for proof in proofs):
        return False
    if any(not isinstance(proof.get("token"), str) or not re.fullmatch(r"[0-9a-f]{32}", proof["token"])
           or not isinstance(proof.get("attribute"), str) or not re.fullmatch(r"data-maher-[0-9a-f]{24}", proof["attribute"])
           or type(proof.get("status")) is not int for proof in proofs):
        return False
    if proofs[0]["token"] == proofs[1]["token"] or proofs[0]["attribute"] == proofs[1]["attribute"]:
        return False
    hashes = {hashlib.sha256(url.encode()).hexdigest() for url in known if _safe_url(url) == finding.get("target")}
    for run in runs:
        if not isinstance(run, dict):
            continue
        if (run.get("tool") != finding.get("source") or run.get("target_sha256") not in hashes
                or run.get("status") not in {"ok", "partial"}):
            continue
        if finding["source"] == "browser-xss-auth" and (
                run.get("identity") != evidence.get("identity") or not run.get("profile_sha256")):
            continue
        for check in run.get("checks", []):
            if (isinstance(check, dict) and check.get("parameter") == evidence.get("parameter")
                    and check.get("occurrence") == evidence.get("occurrence")
                    and check.get("status") == "confirmed_execution" and check.get("control_passed") is True
                    and check.get("proofs") == proofs):
                return True
    return False


def review_agent_evidence(findings, runs, known_urls, scope):
    records = []
    for index, finding in enumerate(findings, 1):
        state, reasons = "needs_independent_validation", []
        if not isinstance(finding, dict):
            state, reasons = "invalid_record", ["finding is not an object"]
        else:
            target = finding.get("target")
            try:
                scoped = isinstance(target, str) and is_in_scope_url(target, scope)
            except ValueError:
                scoped = False
            if not target:
                state, reasons = "insufficient_evidence", ["target not recorded"]
            elif not scoped:
                state, reasons = "outside_scope", ["reported target does not pass configured scope policy"]
            elif not finding.get("evidence"):
                state, reasons = "insufficient_evidence", ["no supporting evidence recorded"]
            elif finding.get("source") in {"browser-xss", "browser-xss-auth"}:
                known_scoped = [url for url in known_urls if is_in_scope_url(url, scope)]
                if _browser_proof_bound(finding, runs, known_scoped):
                    state = "recorded_browser_execution_proof"
                    reasons = ["two distinct marker proofs match a recorded target-bound browser check",
                               "application impact and exploitability still require review"]
                else:
                    reasons = ["browser claim lacks matching complete control/probe records"]
            else:
                reasons = ["scanner message or validated flag alone is not independent execution proof"]
        records.append({"record_id": f"tool-{index}", "review_state": state, "reasons": reasons,
                        "impact_confirmed": False})
    return {"mode": "static_recorded_evidence_review", "records": records,
            "counts": dict(Counter(row["review_state"] for row in records)),
            "limitations": ["record consistency checks only; no independent browser/request executed",
                            "scope uses existing host-based policy, not new path-level authorization",
                            "raw findings retained regardless of review state; no additional vulnerability discovery"]}
