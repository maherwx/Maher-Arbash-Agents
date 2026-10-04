from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

SINK_PATTERNS = {
    "sql": [
        re.compile(r"\bexecute\s*\(", re.I),
        re.compile(r"\bquery\s*\(", re.I),
        re.compile(r"\braw\s*\(", re.I),
        re.compile(r"\bcreatequery\s*\(", re.I),
    ],
    "filesystem": [
        re.compile(r"\bopen\s*\(", re.I),
        re.compile(r"\bwritefile\s*\(", re.I),
        re.compile(r"\breadfile\s*\(", re.I),
        re.compile(r"\bfile\.write", re.I),
    ],
    "process": [
        re.compile(r"\bexec\s*\(", re.I),
        re.compile(r"\bspawn\s*\(", re.I),
        re.compile(r"\bsubprocess\.", re.I),
        re.compile(r"\bprocessbuilder\s*\(", re.I),
    ],
    "http_client": [
        re.compile(r"\bfetch\s*\(", re.I),
        re.compile(r"\baxios\.", re.I),
        re.compile(r"\brequests\.", re.I),
        re.compile(r"\bhttpclient\.", re.I),
        re.compile(r"\bresttemplate\.", re.I),
    ],
}

SOURCE_PATTERNS = {
    "request": [
        re.compile(r"request\.(?:args|form|json|headers|cookies)", re.I),
        re.compile(r"req\.(?:params|query|body|headers|cookies)", re.I),
        re.compile(r"@requestparam|@pathvariable|@requestbody", re.I),
        re.compile(r"httpcontext\.", re.I),
    ],
    "environment": [
        re.compile(r"os\.environ", re.I),
        re.compile(r"process\.env", re.I),
        re.compile(r"system\.getenv", re.I),
        re.compile(r"environment\.getenvironmentvariable", re.I),
    ],
}

ROUTE_PATTERNS = [
    re.compile(r"@(?:get|post|put|patch|delete|route)\s*\(\s*[\"']([^\"']+)", re.I),
    re.compile(r"app\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", re.I),
    re.compile(r"@(?:getmapping|postmapping|putmapping|patchmapping|deletemapping|requestmapping)\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)", re.I),
    re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)\s*\(\s*[\"']([^\"']+)", re.I),
]

@dataclass(slots=True)
class SourceFlowSignal:
    file: str
    line: int
    category: str
    kind: str
    snippet: str
    route_hint: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def _route_hints(text: str) -> list[str]:
    out = []
    for pat in ROUTE_PATTERNS:
        out.extend(pat.findall(text))
    return sorted(set(out))


def analyze_source_flows(root: str | Path, *, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(root)
    exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".cs", ".php", ".rb", ".go", ".rs"}
    signals: list[SourceFlowSignal] = []
    file_routes: dict[str, list[str]] = {}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(part in {".git", "node_modules", "vendor", "target", "dist", "build", ".venv"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(path.relative_to(root))
        routes = _route_hints(text)
        if routes:
            file_routes[rel] = routes
        lines = text.splitlines()

        for lineno, line in enumerate(lines, start=1):
            route_hint = routes[0] if len(routes) == 1 else None
            for kind, patterns in SOURCE_PATTERNS.items():
                if any(p.search(line) for p in patterns):
                    signals.append(SourceFlowSignal(rel, lineno, "source", kind, line.strip()[:500], route_hint))
            for kind, patterns in SINK_PATTERNS.items():
                if any(p.search(line) for p in patterns):
                    signals.append(SourceFlowSignal(rel, lineno, "sink", kind, line.strip()[:500], route_hint))

    by_file = defaultdict(lambda: {"sources": Counter(), "sinks": Counter(), "routes": []})
    for sig in signals:
        bucket = by_file[sig.file]
        bucket["sources" if sig.category == "source" else "sinks"][sig.kind] += 1
        bucket["routes"] = file_routes.get(sig.file, [])

    cross_surface = []
    for file, info in by_file.items():
        if info["sources"] and info["sinks"]:
            cross_surface.append({
                "file": file,
                "routes": info["routes"],
                "sources": dict(info["sources"]),
                "sinks": dict(info["sinks"]),
                "priority": "high" if ("request" in info["sources"] and ("sql" in info["sinks"] or "process" in info["sinks"])) else "medium",
            })

    return {
        "signal_count": len(signals),
        "files_with_routes": len(file_routes),
        "signals": [s.as_dict() for s in signals],
        "cross_surface_candidates": cross_surface,
    }


def correlate_runtime_routes(source_analysis: dict, traffic_records: list[dict]) -> dict:
    runtime = defaultdict(list)
    for rec in traffic_records:
        url = str(rec.get("url", ""))
        if not url:
            continue
        u = urlparse(url)
        runtime[u.path or "/"].append({
            "method": rec.get("method"),
            "status": rec.get("status"),
            "url": url,
            "source": rec.get("source"),
        })

    correlations = []
    for item in source_analysis.get("cross_surface_candidates", []):
        for route in item.get("routes", []):
            matches = []
            for path, observations in runtime.items():
                if route == path or (route.endswith("/{id}") and path.startswith(route[:-5])) or path.startswith(route.rstrip("/")):
                    matches.extend(observations)
            if matches:
                correlations.append({
                    "file": item["file"],
                    "route": route,
                    "priority": item["priority"],
                    "sources": item["sources"],
                    "sinks": item["sinks"],
                    "runtime_observations": matches[:100],
                })
    return {"correlation_count": len(correlations), "correlations": correlations}
