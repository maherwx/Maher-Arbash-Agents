"""Conservative candidate changes between local source review snapshots."""
import hashlib
import json
from pathlib import Path
from .execution_journal import _unique_fields, _invalid_constant


SOURCE_ANALYSIS_REVISION = 2
ANALYSIS_MODES = {"local_python_ast": "python_ast", "local_generic_text": "generic_text", "local_semgrep_ce": "semgrep_ce"}


def _candidates(report):
    rows = report.get("findings", [])
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError("source baseline findings must be a bounded list")
    result = {}
    for row in rows[:200]:
        if not isinstance(row, dict) or not isinstance(row.get("file"), str) or type(row.get("line")) is not int:
            raise ValueError("source baseline candidate is invalid")
        fields = {key: row.get(key) for key in ("file", "line", "source", "cwe", "rule_id", "sink")}
        identifier = hashlib.sha256(json.dumps(fields, sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest()[:24]
        result[identifier] = row
    return result


def compare_source_baseline(current, path):
    result = {"mode": "source_candidate_baseline", "status": "no_previous_snapshot", "changes": [],
              "runtime_fix_verified": False,
              "limitations": ["candidate identity includes file/line/rule; moved lines may appear new",
                              "absence is not proof of a fix; missing coverage remains unknown",
                              "Semgrep version is not pinned, so its missing candidates remain unknown"]}
    if not Path(path).is_file():
        return result
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("source baseline exceeds its byte limit")
        previous = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
        if not isinstance(previous, dict):
            raise ValueError("source baseline must be an object")
        if previous.get("source_root_sha256") != current["source_root_sha256"]:
            result["status"] = "different_or_unbound_source_root"
            return result
        if previous.get("analysis_revision") != current["analysis_revision"] or previous.get("rules_sha256") != current["rules_sha256"]:
            result["status"] = "different_analysis_revision"
            return result
        old, new = _candidates(previous), _candidates(current)
        files = {row["path"]: row for row in current["files"]}
        for identifier in sorted(old.keys() | new.keys()):
            row = new.get(identifier) or old[identifier]
            if identifier in new:
                state = "continuing_candidate" if identifier in old else "new_candidate"
            else:
                file = files.get(row["file"], {})
                mode = ANALYSIS_MODES.get(row.get("source"))
                adequate = mode in file.get("analyses", []) and mode != "semgrep_ce"
                adequate = adequate and not current.get("truncated") and not current.get("skipped")
                state = "not_observed_in_current_review" if adequate else "unknown_due_to_coverage"
            result["changes"].append({"candidate_id": identifier, "file": row["file"], "line": row["line"],
                "source": row.get("source"), "rule_id": row.get("rule_id"), "cwe": row.get("cwe"),
                "state": state, "current_file_sha256": files.get(row["file"], {}).get("sha256"),
                "previous_file_sha256": old.get(identifier, {}).get("file_sha256"),
                "candidate_validated": False, "runtime_fix_verified": False})
        result["status"] = "compared"
        result["counts"] = {state: sum(row["state"] == state for row in result["changes"])
            for state in ("new_candidate", "continuing_candidate", "not_observed_in_current_review", "unknown_due_to_coverage")}
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        result.update({"status": "invalid_previous_snapshot", "error_type": type(error).__name__, "changes": []})
    return result
