from __future__ import annotations

import ast
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(slots=True)
class FunctionModel:
    file: str
    name: str
    line: int
    async_function: bool
    parameters: list[str]
    decorators: list[str]
    calls: list[str]
    reads: list[str]
    writes: list[str]
    returns: int
    branches: int
    loops: int
    exceptions: int
    complexity: int

    def as_dict(self) -> dict:
        return asdict(self)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


class _FunctionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.calls = Counter()
        self.reads = Counter()
        self.writes = Counter()
        self.returns = 0
        self.branches = 0
        self.loops = 0
        self.exceptions = 0

    def visit_Call(self, node: ast.Call):
        name = _name(node.func)
        if name:
            self.calls[name] += 1
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.reads[node.id] += 1
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            self.writes[node.id] += 1

    def visit_Return(self, node: ast.Return):
        self.returns += 1
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        self.branches += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp):
        self.branches += 1
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match):
        self.branches += max(1, len(node.cases))
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self.loops += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self.loops += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self.loops += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self.exceptions += len(node.handlers)
        self.generic_visit(node)


def _decorators(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    out = []
    for dec in node.decorator_list:
        name = _name(dec)
        if name:
            out.append(name)
        elif isinstance(dec, ast.Call):
            name = _name(dec.func)
            if name:
                out.append(name)
    return out


def analyze_python_ast(root: str | Path, *, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(root)
    functions: list[FunctionModel] = []
    imports = Counter()
    parse_errors = []
    call_edges = Counter()
    route_functions = []

    for path in root.rglob("*.py"):
        if any(part in {".git", ".venv", "venv", "build", "dist", "site-packages"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError) as exc:
            parse_errors.append({"file": str(path), "error": str(exc)})
            continue

        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.name] += 1
            elif isinstance(node, ast.ImportFrom):
                imports[node.module or ""] += 1

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            visitor = _FunctionVisitor()
            for statement in node.body:
                visitor.visit(statement)
            decorators = _decorators(node)
            params = [a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
            if node.args.vararg:
                params.append("*" + node.args.vararg.arg)
            if node.args.kwarg:
                params.append("**" + node.args.kwarg.arg)
            complexity = 1 + visitor.branches + visitor.loops + visitor.exceptions
            model = FunctionModel(
                file=rel,
                name=node.name,
                line=node.lineno,
                async_function=isinstance(node, ast.AsyncFunctionDef),
                parameters=params,
                decorators=decorators,
                calls=sorted(visitor.calls),
                reads=sorted(visitor.reads),
                writes=sorted(visitor.writes),
                returns=visitor.returns,
                branches=visitor.branches,
                loops=visitor.loops,
                exceptions=visitor.exceptions,
                complexity=complexity,
            )
            functions.append(model)
            caller = f"{rel}:{node.name}"
            for callee, count in visitor.calls.items():
                call_edges[(caller, callee)] += count
            if any(any(token in d.lower() for token in ("route", ".get", ".post", ".put", ".patch", ".delete")) for d in decorators):
                route_functions.append({"file": rel, "function": node.name, "line": node.lineno, "decorators": decorators, "complexity": complexity})

    return {
        "schema_version": "1.0",
        "file_count": len({f.file for f in functions}),
        "function_count": len(functions),
        "imports": dict(imports.most_common()),
        "functions": [f.as_dict() for f in functions],
        "route_functions": sorted(route_functions, key=lambda x: (-x["complexity"], x["file"], x["line"])),
        "call_edges": [{"caller": caller, "callee": callee, "count": count} for (caller, callee), count in call_edges.most_common()],
        "parse_errors": parse_errors,
    }
