"""Bounded local Python AST review. Never imports or executes submitted code."""
import ast
import hashlib
import json
import os
from pathlib import Path


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
    for region in regions:
        tainted = {}

        def sources(expression):
            nonlocal work
            found = set()
            for item in ast.walk(expression):
                work += 1
                if work > 200000:
                    raise SourceAnalysisLimit("source propagation work limit reached")
                if isinstance(item, ast.Name):
                    found.update(tainted.get(item.id, set()))
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
            if not isinstance(node, ast.Call) or not node.args:
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
                    "evidence": "AST request-source propagation to a sensitive first argument; no runtime proof"})
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
    files, findings, skipped = [], [], {}
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
            if path.suffix != ".py" or path.is_symlink():
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
                tree = ast.parse(data, filename=relative)
                if sum(1 for _ in ast.walk(tree)) > 20000:
                    skipped["ast_limit"] = skipped.get("ast_limit", 0) + 1
                    continue
                rows = _python_findings(tree, relative)[:200 - len(findings)]
                digest = hashlib.sha256(data).hexdigest()
                for row in rows:
                    row["file_sha256"] = digest
                findings.extend(rows)
                files.append({"path": relative, "sha256": digest,
                              "language": "python", "candidate_count": len(rows)})
                if len(findings) >= 200:
                    truncated = True
                    break
            except (OSError, SyntaxError, ValueError, RecursionError) as error:
                kind = type(error).__name__
                skipped[kind] = skipped.get(kind, 0) + 1
        if truncated:
            break
    status = "partial" if skipped or truncated else "completed" if files else "no_supported_source"
    report = {"mode": "local_static_source_review", "status": status,
              "languages": ["python"], "files": files, "findings": findings,
              "file_count": len(files), "candidate_count": len(findings), "skipped": skipped,
              "truncated": truncated, "runtime_verified": False,
              "limitations": ["heuristic intra-region propagation; no interprocedural/control-flow proof",
                              "sanitizers, import shadowing and generic execute methods need manual review",
                              "no source execution, server-source download, JavaScript or other language analysis"]}
    output.mkdir(parents=True, exist_ok=True)
    (output / "source-review.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
