from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

TECH = {
    "python": {"ext": {".py"}, "markers": ["requirements.txt", "pyproject.toml", "manage.py"], "frameworks": {"django": ["django", "urls.py"], "flask": ["flask"], "fastapi": ["fastapi"]}},
    "javascript_typescript": {"ext": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}, "markers": ["package.json", "tsconfig.json"], "frameworks": {"nextjs": ["next", "next.config"], "express": ["express"], "nestjs": ["@nestjs"], "react": ["react"]}},
    "java_kotlin": {"ext": {".java", ".kt", ".kts"}, "markers": ["pom.xml", "build.gradle", "build.gradle.kts"], "frameworks": {"spring": ["spring-boot", "@restcontroller"], "ktor": ["ktor"]}},
    "dotnet": {"ext": {".cs", ".fs", ".vb"}, "markers": [".csproj", ".fsproj", ".sln"], "frameworks": {"aspnet": ["microsoft.aspnetcore", "[apicontroller]"]}},
    "php": {"ext": {".php"}, "markers": ["composer.json"], "frameworks": {"laravel": ["laravel", "artisan"], "symfony": ["symfony"]}},
    "ruby": {"ext": {".rb"}, "markers": ["gemfile"], "frameworks": {"rails": ["rails", "routes.rb"]}},
    "go": {"ext": {".go"}, "markers": ["go.mod"], "frameworks": {"gin": ["gin-gonic"], "fiber": ["gofiber"]}},
    "rust": {"ext": {".rs"}, "markers": ["cargo.toml"], "frameworks": {"actix": ["actix-web"], "axum": ["axum"]}},
    "native": {"ext": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}, "markers": ["cmakelists.txt", "makefile"], "frameworks": {}},
    "swift_objc": {"ext": {".swift", ".m", ".mm"}, "markers": ["package.swift", "podfile"], "frameworks": {"vapor": ["vapor"]}},
}

ROUTE_PATTERNS = [
    re.compile(r"(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", re.I),
    re.compile(r"@(?:get|post|put|patch|delete|requestmapping|getmapping|postmapping|putmapping|deletemapping)\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)", re.I),
    re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)\s*\(\s*[\"']([^\"']+)", re.I),
]


def analyze_source_tree(root: str | Path, *, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(root)
    languages = Counter(); frameworks = Counter(); routes = defaultdict(set); files_scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", "vendor", "target", "dist", "build", ".venv"} for part in path.parts):
            continue
        name = path.name.lower(); ext = path.suffix.lower(); matched = []
        for tech, spec in TECH.items():
            if ext in spec["ext"] or name in spec["markers"]:
                languages[tech] += 1; matched.append(tech)
        if not matched:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1; low = text.lower()
        for tech in matched:
            for fw, needles in TECH[tech]["frameworks"].items():
                if any(n in low for n in needles): frameworks[fw] += 1
        for pattern in ROUTE_PATTERNS:
            for route in pattern.findall(text): routes[str(path.relative_to(root))].add(route)
    return {
        "root": str(root), "files_scanned": files_scanned,
        "technology_counts": dict(languages.most_common()), "framework_signals": dict(frameworks.most_common()),
        "routes": [{"file": f, "routes": sorted(v)} for f, v in sorted(routes.items())],
        "route_count": sum(len(v) for v in routes.values()),
    }


def write_analysis(root: str | Path, out: str | Path) -> dict:
    result = analyze_source_tree(root)
    out = Path(out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
