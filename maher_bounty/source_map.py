"""Bounded source structure map; declarations never become authorized targets."""
import ast
import posixpath
import re
from pathlib import PurePosixPath


def _text(data):
    return data.decode("utf-16") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else data.decode("utf-8-sig")


def _route(value):
    return isinstance(value, str) and len(value) <= 300 and value.startswith("/") and re.fullmatch(r"[/A-Za-z0-9_:{}<>.*-]+", value)


def _local_import(file, reference, known):
    if not reference.startswith(".") or not re.fullmatch(r"[A-Za-z0-9_./-]{1,160}", reference):
        return None
    candidate = posixpath.normpath(posixpath.join(str(PurePosixPath(file).parent), reference))
    if candidate.startswith("../") or candidate.startswith("/"):
        return None
    for suffix in ("", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", "/index.js", "/index.ts", "/index.tsx"):
        if candidate + suffix in known:
            return candidate + suffix
    return None


def build_source_map(snapshots, files, findings):
    known = {row["path"]: row for row in files}
    edges, routes, errors = [], [], {}
    seen_edges = set()
    truncated = False

    def edge(source, target, line, kind):
        nonlocal truncated
        if not target or source == target or (source, target, line) in seen_edges:
            return
        if len(edges) >= 1000:
            truncated = True
            return
        seen_edges.add((source, target, line))
        edges.append({"source_file": source, "target_file": target, "line": line, "kind": kind,
                      "source_sha256": known[source]["sha256"], "target_sha256": known[target]["sha256"]})

    def route(file, line, path, method, start=None, end=None):
        nonlocal truncated
        if not _route(path):
            return
        if len(routes) >= 200:
            truncated = True
            return
        associated = [row["line"] for row in findings if row["file"] == file
                      and start is not None and start <= row["line"] <= end]
        routes.append({"file": file, "file_sha256": known[file]["sha256"], "line": line,
                       "declared_path": path, "method": method, "candidate_lines": sorted(set(associated)),
                       "runtime_verified": False, "authorizes_network_target": False})

    for file, data in snapshots.items():
        language = known[file]["language"]
        if language not in {"python", "javascript", "typescript"}:
            continue
        try:
            text = _text(data)
            if language == "python":
                tree = ast.parse(text, filename=file)
                nodes = list(ast.walk(tree))
                if len(nodes) > 20000:
                    raise ValueError("source map AST limit reached")
                for node in nodes:
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        parent = PurePosixPath(file).parent
                        if isinstance(node, ast.ImportFrom) and node.level:
                            if node.level > len(parent.parts) + 1:
                                continue
                            for _ in range(node.level - 1):
                                parent = parent.parent
                            base = str(parent / (node.module or "").replace(".", "/"))
                            modules = [base, *(base + "/" + alias.name for alias in node.names)]
                        else:
                            if isinstance(node, ast.Import):
                                modules = [alias.name.replace(".", "/") for alias in node.names]
                            else:
                                base = (node.module or "").replace(".", "/")
                                modules = [base, *(base + "/" + alias.name for alias in node.names)]
                        for module in modules:
                            module = posixpath.normpath(module)
                            target = next((value for value in (module + ".py", module + "/__init__.py") if value in known), None)
                            edge(file, target, node.lineno, "python_import")
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for decorator in node.decorator_list:
                            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute) or not decorator.args:
                                continue
                            name = decorator.func.attr.lower()
                            if name not in {"route", "get", "post", "put", "patch", "delete", "head", "options"}:
                                continue
                            argument = decorator.args[0]
                            if isinstance(argument, ast.Constant):
                                method = name.upper() if name != "route" else "unspecified"
                                route(file, decorator.lineno, argument.value, method, node.lineno, node.end_lineno)
            else:
                for match in re.finditer(r"\b(?:from\s*|require\s*\(\s*|import\s*)['\"]([^'\"\n]{1,160})['\"]", text):
                    edge(file, _local_import(file, match.group(1), known), text.count("\n", 0, match.start()) + 1, "relative_module_import")
                for match in re.finditer(r"\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"\n]{1,300})['\"]", text):
                    route(file, text.count("\n", 0, match.start()) + 1, match.group(2), match.group(1).upper())
        except (SyntaxError, ValueError, UnicodeError, RecursionError) as error:
            kind = type(error).__name__
            errors[kind] = errors.get(kind, 0) + 1
    ranked = []
    for file, metadata in known.items():
        candidates = [row for row in findings if row["file"] == file]
        imported_by = sum(1 for row in edges if row["target_file"] == file)
        declarations = sum(1 for row in routes if row["file"] == file)
        if candidates or imported_by or declarations:
            ranked.append({"file": file, "file_sha256": metadata["sha256"], "candidate_count": len(candidates),
                           "import_edge_count": imported_by, "route_declarations": declarations,
                           "review_priority_score": len(candidates) * 5 + declarations * 2 + min(imported_by, 10)})
    ranked.sort(key=lambda row: (-row["review_priority_score"], row["file"]))
    return {"mode": "local_source_structure", "import_edges": edges, "route_declarations": routes,
            "priority_files": ranked[:30], "truncated": truncated, "errors": errors,
            "runtime_verified": False, "network_scope_expanded": False,
            "limitations": ["Python imports/decorators and JS/TS relative imports/route text only",
                            "no runtime route prefixes, dependency versions, whole-program call graph or exploit proof",
                            "Python candidate-to-route containment is lexical; JS/TS routes have no handler dataflow link"]}
