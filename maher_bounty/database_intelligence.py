from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

DB_MARKERS = {
    "postgresql": [r"postgres(?:ql)?://", r"psycopg", r"pgx", r"npgsql", r"org\.postgresql"],
    "mysql_mariadb": [r"mysql://", r"mariadb://", r"pymysql", r"mysqlclient", r"mysql2", r"com\.mysql"],
    "sqlite": [r"sqlite://", r"sqlite3", r"microsoft\.data\.sqlite"],
    "sqlserver": [r"sqlserver://", r"mssql", r"sqlclient", r"jdbc:sqlserver"],
    "mongodb": [r"mongodb(?:\+srv)?://", r"mongoose", r"pymongo", r"mongodb\.driver"],
    "redis": [r"redis://", r"ioredis", r"stackexchange\.redis", r"jedis"],
    "elasticsearch_opensearch": [r"elasticsearch", r"opensearch"],
}

ORM_MARKERS = {
    "sqlalchemy": [r"sqlalchemy", r"session\.query", r"select\("],
    "django_orm": [r"\.objects\.(?:filter|get|exclude|create|update)", r"django\.db"],
    "hibernate_jpa": [r"entitymanager", r"@entity", r"hibernate", r"spring-data-jpa"],
    "entity_framework": [r"dbcontext", r"dbset<", r"entityframeworkcore"],
    "prisma": [r"@prisma/client", r"prisma\.[a-z_]"],
    "sequelize": [r"sequelize", r"model\.(?:find|create|update|destroy)"],
    "typeorm": [r"typeorm", r"getrepository\("],
    "laravel_eloquent": [r"illuminate\\database", r"::where\(", r"eloquent"],
    "rails_activerecord": [r"activerecord", r"\.where\(", r"find_by\("],
    "gorm": [r"gorm\.io/gorm", r"db\.(?:where|find|first|create|save)\("],
    "diesel": [r"diesel::", r"table!\("],
}

RAW_QUERY_MARKERS = [
    re.compile(r"\bexecute\s*\(\s*(?:f|rf)?[\"'].*(?:select|insert|update|delete)", re.I),
    re.compile(r"\bquery\s*\(\s*(?:f|rf)?[\"'].*(?:select|insert|update|delete)", re.I),
    re.compile(r"\bfromsql(?:raw|interpolated)?\s*\(", re.I),
    re.compile(r"\bcreateNativeQuery\s*\(", re.I),
    re.compile(r"DB::raw\s*\(", re.I),
]

@dataclass(slots=True)
class DatabaseSignal:
    file: str
    line: int
    kind: str
    technology: str
    snippet: str

    def as_dict(self) -> dict:
        return asdict(self)


def analyze_database_usage(root: str | Path, *, max_file_bytes: int = 2_000_000) -> dict:
    root = Path(root)
    exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".cs", ".php", ".rb", ".go", ".rs", ".json", ".yaml", ".yml", ".toml", ".xml", ".properties", ".env"}
    db_counts = Counter(); orm_counts = Counter(); signals: list[DatabaseSignal] = []
    raw_query_sites = []

    compiled_db = {name: [re.compile(p, re.I) for p in pats] for name, pats in DB_MARKERS.items()}
    compiled_orm = {name: [re.compile(p, re.I) for p in pats] for name, pats in ORM_MARKERS.items()}

    for path in root.rglob("*"):
        if not path.is_file() or (path.suffix.lower() not in exts and path.name.lower() not in {"gemfile", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts"}):
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
        lines = text.splitlines()
        low = text.lower()

        for db, patterns in compiled_db.items():
            if any(p.search(low) for p in patterns):
                db_counts[db] += 1

        for orm, patterns in compiled_orm.items():
            if any(p.search(low) for p in patterns):
                orm_counts[orm] += 1

        for lineno, line in enumerate(lines, start=1):
            for db, patterns in compiled_db.items():
                if any(p.search(line) for p in patterns):
                    signals.append(DatabaseSignal(rel, lineno, "database", db, line.strip()[:500]))
            for orm, patterns in compiled_orm.items():
                if any(p.search(line) for p in patterns):
                    signals.append(DatabaseSignal(rel, lineno, "orm", orm, line.strip()[:500]))
            if any(p.search(line) for p in RAW_QUERY_MARKERS):
                raw_query_sites.append({"file": rel, "line": lineno, "snippet": line.strip()[:500]})

    return {
        "database_counts": dict(db_counts.most_common()),
        "orm_counts": dict(orm_counts.most_common()),
        "raw_query_site_count": len(raw_query_sites),
        "raw_query_sites": raw_query_sites,
        "signals": [s.as_dict() for s in signals],
    }
