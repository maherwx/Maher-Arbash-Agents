from __future__ import annotations

import shutil
from .zap_cli import find_zap_executable
from typing import Iterable


# Tool names are executable names; imports/manual products are deliberately not invoked.
CATALOG = (
    {"name": "subfinder", "command": "subfinder", "areas": {"domain"}, "mode": "passive"},
    {"name": "assetfinder", "command": "assetfinder", "areas": {"domain"}, "mode": "passive"},
    {"name": "waybackurls", "command": "waybackurls", "areas": {"domain", "web"}, "mode": "passive"},
    {"name": "gau", "command": "gau", "areas": {"domain", "web"}, "mode": "passive"},
    {"name": "dnsx", "command": "dnsx", "areas": {"domain", "dns"}, "mode": "active"},
    {"name": "alterx", "command": "alterx", "areas": {"domain", "dns"}, "mode": "active"},
    {"name": "httpx", "command": "httpx", "areas": {"web", "api"}, "mode": "passive"},
    {"name": "whatweb", "command": "whatweb", "areas": {"web"}, "mode": "passive"},
    {"name": "wafw00f", "command": "wafw00f", "areas": {"web"}, "mode": "passive"},
    {"name": "katana", "command": "katana", "areas": {"web", "javascript", "api"}, "mode": "active"},
    {"name": "nuclei", "command": "nuclei", "areas": {"web", "api", "cms", "tls"}, "mode": "active"},
    {"name": "nikto", "command": "nikto", "areas": {"web"}, "mode": "active"},
    {"name": "dalfox", "command": "dalfox", "areas": {"javascript", "web"}, "mode": "active"},
    {"name": "naabu", "command": "naabu", "areas": {"network"}, "mode": "active"},
    {"name": "nmap", "command": "nmap", "areas": {"network", "tls"}, "mode": "active"},
    {"name": "tlsx", "command": "tlsx", "areas": {"tls"}, "mode": "active"},
    {"name": "sslscan", "command": "sslscan", "areas": {"tls"}, "mode": "active"},
    {"name": "ffuf", "command": "ffuf", "areas": {"web", "api"}, "mode": "active"},
    {"name": "gobuster", "command": "gobuster", "areas": {"web", "api"}, "mode": "active"},
    {"name": "zap-baseline", "command": "zap-baseline.py", "areas": {"web", "api"}, "mode": "passive"},
    {"name": "Burp Suite", "command": None, "areas": {"web", "api"}, "mode": "manual_proxy_report_import"},
    {"name": "Semgrep", "command": "semgrep", "areas": {"source"}, "mode": "static"},
    {"name": "Bandit", "command": "bandit", "areas": {"source", "python"}, "mode": "static"},
    {"name": "pip-audit", "command": "pip-audit", "areas": {"source", "python"}, "mode": "static"},
    {"name": "npm-audit", "command": "npm", "areas": {"source", "javascript"}, "mode": "static"},
    {"name": "govulncheck", "command": "govulncheck", "areas": {"source", "go"}, "mode": "static"},
    {"name": "Trivy", "command": "trivy", "areas": {"source", "container"}, "mode": "static"},
    {"name": "gitleaks", "command": "gitleaks", "areas": {"source", "secrets"}, "mode": "static"},
)


SIGNAL_RULES = (
    ("python", {"python", "django", "flask", "fastapi", "gunicorn", "uvicorn"}),
    ("javascript", {"javascript", "typescript", "node", "react", "next.js", "nextjs", "angular", "vue"}),
    ("java", {"java", "spring", "tomcat", "kotlin"}),
    ("dotnet", {"asp.net", "aspnet", ".net", "iis"}),
    ("php", {"php", "laravel", "symfony", "wordpress", "drupal"}),
    ("go", {"golang", "go"}),
    ("api", {"api", "graphql", "openapi", "swagger", "json"}),
    ("cms", {"wordpress", "drupal", "joomla", "magento"}),
    ("tls", {"tls", "https", "nginx", "apache", "cloudflare"}),
    ("container", {"docker", "kubernetes", "container"}),
)


def _strings(value) -> Iterable[str]:
    if isinstance(value, str):
        yield value.lower()
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield str(key).lower()
            yield from _strings(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _strings(nested)


def infer_areas(inventory: dict | None) -> set[str]:
    inventory = inventory if isinstance(inventory, dict) else {}
    haystack = " ".join(_strings(inventory))
    areas = {"domain"}
    if inventory.get("http") or inventory.get("endpoints") or any(x in haystack for x in ("http", "https", "web", "server")):
        areas.add("web")
    if any(x in haystack for x in ("api", "graphql", "openapi", "swagger")):
        areas.add("api")
    if any(x in haystack for x in ("javascript", "typescript", "react", "next.js", "node", "vue", "angular")):
        areas.add("javascript")
    if any(x in haystack for x in ("tls", "https", "certificate", "nginx", "apache")):
        areas.add("tls")
    if any(x in haystack for x in ("wordpress", "drupal", "joomla", "magento", "cms")):
        areas.add("cms")
    if any(x in haystack for x in ("python", "django", "flask", "fastapi")):
        areas.update({"python", "source"})
    if any(x in haystack for x in ("golang", "go.mod")):
        areas.update({"go", "source"})
    if any(x in haystack for x in ("docker", "kubernetes", "container")):
        areas.update({"container", "source"})
    if inventory.get("source_tree") or inventory.get("technology_counts"):
        areas.add("source")
    return areas


def recommend_tools(inventory: dict | None = None, *, include_active: bool = False) -> dict:
    """Rank relevant integrations from observed inventory; never launches tools or changes URLs."""
    areas = infer_areas(inventory)
    recommendations = []
    for item in CATALOG:
        overlap = areas.intersection(item["areas"])
        if not overlap:
            continue
        if item["mode"] == "active" and not include_active:
            state = "authorization_required"
        elif item["mode"] == "manual_proxy_report_import":
            state = "manual_or_report_import"
        elif item["command"] is None:
            state = "manual_or_report_import"
        else:
            executable = find_zap_executable() if item["command"] == "zap-baseline.py" else shutil.which(item["command"])
            state = "available" if executable else "not_installed"
        recommendations.append({
            "name": item["name"],
            "command": item["command"],
            "mode": item["mode"],
            "state": state,
            "matched_areas": sorted(overlap),
        })
    recommendations.sort(key=lambda row: (
        row["state"] not in {"available", "manual_or_report_import"},
        row["mode"] == "active" and not include_active,
        row["name"].lower(),
    ))
    return {
        "areas": sorted(areas),
        "active_tools_included": bool(include_active),
        "execution": "recommendations_only",
        "tools": recommendations,
    }
