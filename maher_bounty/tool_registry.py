from __future__ import annotations

import shutil
from dataclasses import dataclass, asdict


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    category: str
    mode: str
    evidence: str
    required: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


TOOLS = (
    ToolSpec("python3", "runtime", "local", "runtime", True),
    ToolSpec("git", "runtime", "local", "source"),
    ToolSpec("go", "runtime", "local", "runtime"),
    ToolSpec("cargo", "runtime", "local", "runtime"),
    ToolSpec("node", "runtime", "local", "runtime"),
    ToolSpec("npm", "runtime", "local", "runtime"),
    ToolSpec("subfinder", "discovery", "passive", "host"),
    ToolSpec("assetfinder", "discovery", "passive", "host"),
    ToolSpec("waybackurls", "archive", "passive", "url"),
    ToolSpec("gau", "archive", "passive", "url"),
    ToolSpec("httpx", "http", "passive", "http"),
    ToolSpec("whatweb", "fingerprint", "passive", "technology"),
    ToolSpec("wafw00f", "fingerprint", "passive", "technology"),
    ToolSpec("dnsx", "dns", "active", "dns"),
    ToolSpec("naabu", "network", "active", "port"),
    ToolSpec("katana", "crawl", "active", "url"),
    ToolSpec("nuclei", "template-analysis", "active", "finding"),
    ToolSpec("tlsx", "tls", "active", "tls"),
    ToolSpec("alterx", "discovery", "active", "host"),
    ToolSpec("hakrawler", "crawl", "active", "url"),
    ToolSpec("dalfox", "validation", "active", "finding"),
    ToolSpec("nmap", "network", "active", "service"),
    ToolSpec("ffuf", "content-discovery", "active", "url"),
    ToolSpec("gobuster", "content-discovery", "active", "url"),
    ToolSpec("nikto", "web-review", "active", "finding"),
)


def tool_status() -> dict:
    rows = []
    for spec in TOOLS:
        path = shutil.which(spec.name)
        rows.append({**spec.as_dict(), "path": path, "available": bool(path)})
    return {
        "tools": rows,
        "available": sum(1 for row in rows if row["available"]),
        "total": len(rows),
        "required_missing": [row["name"] for row in rows if row["required"] and not row["available"]],
        "categories": sorted({row["category"] for row in rows}),
    }


def select_tools(*, allow_active: bool = False, categories: set[str] | None = None) -> list[dict]:
    status = tool_status()["tools"]
    selected = []
    for row in status:
        if categories and row["category"] not in categories:
            continue
        if row["mode"] == "active" and not allow_active:
            continue
        if row["available"]:
            selected.append(row)
    return selected
