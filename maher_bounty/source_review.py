"""Bounded multilingual source review. Never imports or executes submitted code."""
import ast
import hashlib
import json
import os
import re
from pathlib import Path
from .source_languages import language_for, generic_candidates
from .source_semgrep import review_semgrep
from .source_map import build_source_map
from .artifact_io import write_json_atomic
from .source_baseline import compare_source_baseline, SOURCE_ANALYSIS_REVISION
from .source_languages import CHECKS
from .source_semgrep import PATTERNS


EXCLUDED = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", "build", "dist"}
REQUEST_FIELDS = {"args", "form", "values", "json", "get_json", "GET", "POST", "query_params", "data", "body", "cookies", "headers"}


class SourceAnalysisLimit(ValueError):
    pass


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return prefix + "." + node.attr if prefix else node.attr
    return ""


def _walk_region(node):
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from _walk_region(child)


def _python_findings(tree, relative):
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + "." + alias.name

    def canonical(node):
        value = _name(node)
        head, _, suffix = value.partition(".")
        return aliases.get(head, head) + ("." + suffix if suffix else "")

    findings, seen = [], set()
    work = 0
    regions = [tree, *(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))]
    functions = {}
    duplicate_names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in functions:
                duplicate_names.add(node.name)
            functions[node.name] = node
    functions = {name: node for name, node in functions.items() if name not in duplicate_names and name not in aliases}
    incoming, returned = {}, {}
    # Four bounded passes carry positional/keyword inputs and return-source
    # summaries through directly named functions in this file only.
    for region in regions * 4:
        tainted = {name: set(lines) for name, lines in incoming.get(region, {}).items()}
        if isinstance(region, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = [*region.args.posonlyargs, *region.args.args, *region.args.kwonlyargs]
            defaults = [None] * (len(region.args.posonlyargs) + len(region.args.args) - len(region.args.defaults)) + list(region.args.defaults) + list(region.args.kw_defaults)
            path_parameters = set()
            for decorator in region.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr in {"route", "get", "post", "put", "patch", "delete", "head", "options"} and decorator.args:
                    path = decorator.args[0]
                    if isinstance(path, ast.Constant) and isinstance(path.value, str) and path.value.startswith("/"):
                        path_parameters.update(re.findall(r"\{([A-Za-z_]\w*)\}|<(?:[A-Za-z_]+:)?([A-Za-z_]\w*)>", path.value))
            path_names = {value for pair in path_parameters for value in pair if value}
            for parameter, default in zip(parameters, defaults):
                markers = [default, parameter.annotation]
                explicit_input = any(isinstance(item, ast.Call) and canonical(item.func) in {
                    "fastapi.Query", "fastapi.Path", "fastapi.Body", "fastapi.Form", "fastapi.Header", "fastapi.Cookie"
                } for marker in markers if marker is not None for item in ast.walk(marker))
                if parameter.arg in path_names or explicit_input:
                    tainted.setdefault(parameter.arg, set()).add(parameter.lineno)

        def sources(expression):
            nonlocal work
            found = set()
            for item in ast.walk(expression):
                work += 1
                if work > 200000:
                    raise SourceAnalysisLimit("source propagation work limit reached")
                if isinstance(item, ast.Name):
                    found.update(tainted.get(item.id, set()))
                if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id in functions:
                    found.update(returned.get(item.func.id, set()))
                if isinstance(item, ast.Attribute) and item.attr in REQUEST_FIELDS:
                    owner = canonical(item.value).split(".")
                    if "request" in owner or "req" in owner:
                        found.add(item.lineno)
            return found

        for node in _walk_region(region):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = node.value
                if value is not None:
                    origin = sources(value)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    # Union is conservative for branches and repeated assignments.
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name) and origin:
                                tainted.setdefault(name.id, set()).update(origin)
            if isinstance(node, ast.Return) and node.value is not None and isinstance(region, (ast.FunctionDef, ast.AsyncFunctionDef)) and functions.get(region.name) is region:
                returned.setdefault(region.name, set()).update(sources(node.value))
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in functions:
                callee = functions[node.func.id]
                bindings = incoming.setdefault(callee, {})
                positional = [*callee.args.posonlyargs, *callee.args.args]
                positional_arguments = [] if any(isinstance(argument, ast.Starred) for argument in node.args) else node.args
                for parameter, argument in zip(positional, positional_arguments):
                    bindings.setdefault(parameter.arg, set()).update(sources(argument))
                names = {parameter.arg for parameter in [*positional, *callee.args.kwonlyargs]}
                for keyword in node.keywords:
                    if keyword.arg in names:
                        bindings.setdefault(keyword.arg, set()).update(sources(keyword.value))
            if not node.args:
                continue
            origin = sources(node.args[0])
            if not origin:
                continue
            sink = canonical(node.func)
            issue = None
            if sink in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                issue = ("CWE-95", "Request-derived input reaches dynamic code evaluation")
            elif sink == "os.system" or (sink in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
                    and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)):
                issue = ("CWE-78", "Request-derived input reaches a shell command")
            elif sink in {"pickle.loads", "pickle.load"}:
                issue = ("CWE-502", "Request-derived input reaches pickle deserialization")
            elif sink.endswith(".execute") or sink.endswith(".executemany"):
                issue = ("CWE-89", "Request-derived input reaches a SQL execution argument")
            elif sink in {"flask.render_template_string", "render_template_string"}:
                issue = ("CWE-1336", "Request-derived input reaches a template body")
            elif sink in {"flask.send_file", "send_file"}:
                issue = ("CWE-22", "Request-derived input reaches a file response path")
            if issue and (node.lineno, issue[0]) not in seen:
                seen.add((node.lineno, issue[0]))
                findings.append({"title": issue[1], "cwe": issue[0], "file": relative,
                    "line": node.lineno, "source_lines": sorted(origin), "sink": sink,
                    "source": "local_python_ast", "validated": False,
                    "status": "needs_review", "confidence": "heuristic",
                    "evidence": "Bounded AST request-source propagation, including direct local calls, to a sensitive first argument; no runtime proof"})
                if len(findings) >= 200:
                    return findings
    return findings


def review_source(source_dir, out_dir):
    root = Path(source_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source review requires a directory")
    output = Path(out_dir).resolve()
    if root.is_relative_to(output):
        raise ValueError("source review output must not contain the source root")
    files, findings, skipped, snapshots = [], [], {}, {}
    consumed = visited = directories = 0
    truncated = False
    def directory_error(error):
        skipped["directory_errors"] = skipped.get("directory_errors", 0) + 1

    for current, children, names in os.walk(root, followlinks=False, onerror=directory_error):
        directories += 1
        children[:] = sorted(name for name in children if name not in EXCLUDED
            and not (Path(current) / name).is_symlink()
            and not (Path(current) / name).resolve().is_relative_to(output))
        if directories > 500:
            truncated = True
            break
        for name in sorted(names):
            visited += 1
            if visited > 4000 or len(files) >= 200 or consumed >= 8 * 1024 * 1024 or len(findings) >= 200:
                truncated = True
                break
            path = Path(current) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            try:
                if not path.resolve().is_relative_to(root) or not path.is_file():
                    continue
                with path.open("rb") as stream:
                    data = stream.read(256 * 1024 + 1)
                if len(data) > 256 * 1024 or consumed + len(data) > 8 * 1024 * 1024:
                    skipped["size_limit"] = skipped.get("size_limit", 0) + 1
                    continue
                consumed += len(data)
                try:
                    text = data.decode("utf-16") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else data.decode("utf-8-sig")
                except UnicodeError:
                    skipped["binary_or_encoding"] = skipped.get("binary_or_encoding", 0) + 1
                    continue
                if "\x00" in text:
                    skipped["binary_or_encoding"] = skipped.get("binary_or_encoding", 0) + 1
                    continue
                digest = hashlib.sha256(data).hexdigest()
                language = language_for(path, text)
                rows = generic_candidates(text, relative, digest)
                analyses = ["generic_text"]
                if language == "python":
                    try:
                        tree = ast.parse(text, filename=relative)
                        if sum(1 for _ in ast.walk(tree)) > 20000:
                            raise SourceAnalysisLimit("AST node limit reached")
                        rows = _python_findings(tree, relative) + rows
                        analyses.append("python_ast")
                    except (SyntaxError, ValueError, RecursionError) as error:
                        kind = type(error).__name__
                        skipped[kind] = skipped.get(kind, 0) + 1
                rows = rows[:200 - len(findings)]
                for row in rows:
                    row["file_sha256"] = digest
                findings.extend(rows)
                snapshots[relative] = data
                files.append({"path": relative, "sha256": digest,
                              "language": language, "analyses": analyses, "candidate_count": len(rows)})
                if len(findings) >= 200:
                    truncated = True
                    break
            except (OSError, SyntaxError, ValueError, RecursionError) as error:
                kind = type(error).__name__
                skipped[kind] = skipped.get(kind, 0) + 1
        if truncated:
            break
    engine, structural = review_semgrep(snapshots, files)
    available = max(0, 200 - len(findings))
    if len(structural) > available:
        truncated = True
    findings.extend(structural[:available])
    for file in files:
        if file["path"] in engine["scanned_files"]:
            file["analyses"].append("semgrep_ce")
        file["candidate_count"] = sum(1 for row in findings if row["file"] == file["path"])
    coverage = {}
    for file in files:
        row = coverage.setdefault(file["language"], {"file_count": 0, "analysis_modes": set(), "parser_reviewed_files": 0})
        row["file_count"] += 1
        row["analysis_modes"].update(file["analyses"])
        row["parser_reviewed_files"] += int(bool(set(file["analyses"]) & {"python_ast", "semgrep_ce"}))
    for row in coverage.values():
        row["analysis_modes"] = sorted(row["analysis_modes"])
    gaps = [name for name, row in coverage.items() if row["parser_reviewed_files"] < row["file_count"]]
    structure = build_source_map(snapshots, files, findings)
    status = "partial" if skipped or truncated or gaps or structure["truncated"] or structure["errors"] or engine["status"] not in {"ok", "not_applicable"} else "completed" if files else "no_supported_source"
    report = {"mode": "local_static_source_review", "status": status,
              "source_root_sha256": hashlib.sha256(str(root).encode("utf-8")).hexdigest(),
              "analysis_revision": SOURCE_ANALYSIS_REVISION,
              "rules_sha256": hashlib.sha256(json.dumps({"generic": CHECKS, "semgrep": PATTERNS},
                                          sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest(),
              "languages": sorted(coverage), "language_coverage": coverage, "parser_coverage_gaps": gaps,
              "engines": [engine], "files": files, "findings": findings,
              "source_structure": structure,
              "file_count": len(files), "candidate_count": len(findings), "skipped": skipped,
              "truncated": truncated, "runtime_verified": False,
              "limitations": ["four-pass same-file direct-call propagation; no whole-program/control-flow proof",
                              "sanitizers, import shadowing and generic execute methods need manual review",
                              "generic text checks work across text languages but do not prove dataflow",
                              "parser coverage depends on configured local rules and installed CE support",
                              "binary files and unsupported encodings are not reviewed; no server-source download"]}
    report["baseline_comparison"] = compare_source_baseline(report, output / "source-review.json")
    # The primary report embeds its structure and is replaced last. Readers of
    # both artifacts must compare generation IDs, since two replaces are not
    # a cross-file transaction and concurrent writers can interleave them.
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    generation = hashlib.sha256(encoded).hexdigest()
    report["artifact_generation"] = generation
    structure["artifact_generation"] = generation
    write_json_atomic(output / "source-structure.json", structure)
    write_json_atomic(output / "source-review.json", report)
    return report
