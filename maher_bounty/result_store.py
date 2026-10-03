from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable


def stable_id(kind: str, value: str) -> str:
    raw = f"{kind}:{value.strip()}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]


def unique_lines(paths: Iterable[Path]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                values.add(value)
    return sorted(values)


def build_inventory(result_dir: str | Path) -> dict:
    root = Path(result_dir)
    subs = unique_lines([root / "subfinder.txt", root / "assetfinder.txt", root / "subdomains.txt"])
    urls = unique_lines([root / "wayback.txt", root / "gau.txt", root / "archive-urls.txt"])

    hosts = [{"id": stable_id("host", value), "value": value} for value in subs]
    endpoints = [{"id": stable_id("url", value), "value": value} for value in urls]

    http = []
    httpx = root / "httpx.jsonl"
    if httpx.exists():
        for line in httpx.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("url") or row.get("input")
            if url:
                http.append({
                    "id": stable_id("http", url),
                    "url": url,
                    "status_code": row.get("status_code"),
                    "title": row.get("title"),
                    "technologies": row.get("tech", []),
                })

    inventory = {
        "counts": {"hosts": len(hosts), "endpoints": len(endpoints), "http": len(http)},
        "hosts": hosts,
        "endpoints": endpoints,
        "http": http,
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    return inventory
