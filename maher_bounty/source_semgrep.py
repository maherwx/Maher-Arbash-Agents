"""Optional local CE parser checks over the bounded source snapshot only."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import yaml
from .process_runtime import run, OutputLimitExceeded


PATTERNS = {
    "javascript": ["eval($X)", "$OBJ.innerHTML = $X", "child_process.exec($X, ...)"],
    "typescript": ["eval($X)", "$OBJ.innerHTML = $X", "child_process.exec($X, ...)"],
    "java": ["Runtime.getRuntime().exec($X)", "$STMT.executeQuery($X)"],
    "go": ['exec.Command("sh", "-c", $X, ...)'],
    "php": ["eval($X)", "unserialize($X)", "shell_exec($X)"],
    "ruby": ["eval($X)", "system($X)", "Marshal.load($X)"],
    "c": ["system($X)", "strcpy($DST, $SRC)", "gets($DST)"],
    "cpp": ["system($X)", "strcpy($DST, $SRC)"],
    "rust": ['Command::new("sh").arg("-c").arg($X)'],
}


def _review_semgrep(snapshots, files):
    languages = sorted({row["language"] for row in files} & PATTERNS.keys())
    metadata = {"tool": "semgrep", "mode": "local_ce_rules", "rule_languages": languages,
                "status": "not_applicable", "scanned_files": [], "error_count": 0}
    if not languages:
        return metadata, []
    binary = shutil.which("semgrep")
    if not binary:
        metadata["status"] = "missing"
        return metadata, []
    rules, rule_ids = [], set()
    for language in languages:
        for index, pattern in enumerate(PATTERNS[language]):
            identifier = f"maher-{language}-sensitive-sink-{index}"
            rule_ids.add(identifier)
            rules.append({"id": identifier, "languages": [language], "pattern": pattern,
                          "message": "Sensitive API or sink requires manual input/control review", "severity": "WARNING"})
    known = {row["path"]: row for row in files}
    with tempfile.TemporaryDirectory(prefix="maher-source-") as directory:
        staging = Path(directory)
        source = staging / "source"
        for relative, data in snapshots.items():
            if known[relative]["language"] not in languages:
                continue
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        config = staging / "rules.yaml"
        config.write_text(yaml.safe_dump({"rules": rules}), encoding="utf-8")
        command = [binary, "scan", "--config", str(config), "--json", "--quiet", "--oss-only",
                   "--metrics", "off", "--disable-version-check", "--no-secrets-validation",
                   "--no-git-ignore", "--no-rewrite-rule-ids", "--jobs", "2", "--timeout", "5", str(source)]
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("SEMGREP_")}
        environment.update({"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
        try:
            completed = run(command, capture_output=True, text=True, timeout=120,
                            max_output_bytes=4 * 1024 * 1024, env=environment)
            data = json.loads(completed.stdout or "{}")
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise ValueError("invalid local scanner output")
            metadata["status"] = "ok" if completed.returncode == 0 and not data.get("errors") else "partial"
            metadata["returncode"] = completed.returncode
            metadata["error_count"] = len(data.get("errors", [])) if isinstance(data.get("errors"), list) else 1
            metadata["result_truncated"] = len(data["results"]) > 200
            if metadata["result_truncated"]:
                metadata["status"] = "partial"

            def relative_path(value):
                if not isinstance(value, str):
                    return None
                path = Path(value)
                if not path.is_absolute():
                    if value in known:
                        path = source / path
                    else:
                        path = staging / path
                try:
                    relative = path.resolve().relative_to(source.resolve()).as_posix()
                except ValueError:
                    return None
                return relative if relative in known else None

            paths = data.get("paths", {})
            scanned = paths.get("scanned", []) if isinstance(paths, dict) else []
            metadata["scanned_files"] = sorted({relative for value in scanned
                if (relative := relative_path(value)) is not None}) if isinstance(scanned, list) else []
            findings = []
            for item in data["results"][:200]:
                if not isinstance(item, dict) or item.get("check_id") not in rule_ids:
                    continue
                relative = relative_path(item.get("path"))
                start = item.get("start", {})
                line = start.get("line") if isinstance(start, dict) else None
                if relative is None or type(line) is not int or line < 1:
                    continue
                findings.append({"title": "Sensitive API or sink requires manual input/control review",
                    "file": relative, "file_sha256": known[relative]["sha256"], "line": line,
                    "rule_id": item["check_id"], "source": "local_semgrep_ce", "validated": False,
                    "status": "needs_review", "confidence": "structural_pattern",
                    "evidence": "Local parser rule matched a sensitive sink; no input-taint or runtime proof"})
            return metadata, findings
        except OutputLimitExceeded:
            metadata["status"] = "output_limit"
        except subprocess.TimeoutExpired:
            metadata["status"] = "timeout"
        except (OSError, ValueError, RecursionError) as error:
            metadata.update({"status": "error", "error_type": type(error).__name__})
        return metadata, []


def review_semgrep(snapshots, files):
    try:
        return _review_semgrep(snapshots, files)
    except (OSError, ValueError, RecursionError) as error:
        # Staging/configuration failures must preserve the native review results.
        return {"tool": "semgrep", "mode": "local_ce_rules", "status": "error",
                "rule_languages": sorted({row["language"] for row in files} & PATTERNS.keys()),
                "scanned_files": [], "error_count": 1, "error_type": type(error).__name__}, []
