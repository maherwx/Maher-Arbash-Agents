"""Read-only availability snapshot for the fixed local agent tool adapters."""
import importlib.util
import shutil

from .agent_tool_router import SUPPORTED_AGENT_TOOLS


EXECUTABLES = {
    "hakrawler": ("hakrawler",), "katana": ("katana",), "httpx": ("httpx",),
    "nuclei": ("nuclei",), "dalfox": ("dalfox",),
    "zap-baseline.py": ("zap-baseline.py", "zaproxy", "zap.sh"),
    "sslscan": ("sslscan",), "nikto": ("nikto",), "nmap": ("nmap",),
    "tlsx": ("tlsx",), "whatweb": ("whatweb",), "wafw00f": ("wafw00f",),
    "dnsx": ("dnsx",), "naabu": ("naabu",), "ffuf": ("ffuf",),
    "gobuster": ("gobuster",), "subfinder": ("subfinder",),
    "assetfinder": ("assetfinder",), "waybackurls": ("waybackurls",),
    "gau": ("gau",), "alterx": ("alterx",),
}

TOOL_DESCRIPTIONS = {
    "browser-xss": "\u0641\u062d\u0635 \u0645\u062d\u0644\u064a \u0644\u0644\u0645\u062a\u0635\u0641\u062d (Playwright)",
    "browser-xss-auth": "\u064a\u062a\u0637\u0644\u0628 \u0645\u0644\u0641 \u0633\u064a\u0631 \u0639\u0645\u0644 \u0645\u0635\u0627\u062f\u0642\u0627\u062a\u060c \u0644\u064a\u0633 \u062a\u0634\u063a\u064a\u0644\u064b\u0627 \u0645\u0628\u0627\u0634\u0631\u064b\u0627",
    "zap-baseline.py": "\u0645\u062d\u0648\u0651\u0644 ZAP \u0627\u0644\u0645\u062d\u0644\u064a \u0623\u0648 \u0648\u0627\u062c\u0647\u0629 ZAP CLI",
}


def tool_readiness_snapshot():
    """Report fixed-adapter prerequisites using PATH/package metadata only.

    This deliberately does not launch commands, inspect browser installations,
    access targets, or claim that an executable will complete successfully.
    """
    rows = []
    for name in sorted(SUPPORTED_AGENT_TOOLS):
        if name == "browser-xss-auth":
            rows.append({"tool": name, "status": "workflow_only", "available": False,
                         "detail": TOOL_DESCRIPTIONS[name]})
        elif name == "browser-xss":
            try:
                dependency_present = importlib.util.find_spec("playwright") is not None
            except (ImportError, ValueError):
                dependency_present = False
            rows.append({"tool": name,
                         "status": "dependency_present_browser_unverified" if dependency_present else "dependency_missing",
                         "available": dependency_present,
                         "detail": TOOL_DESCRIPTIONS[name] + "; \u062a\u062b\u0628\u064a\u062a \u0627\u0644\u0645\u062a\u0635\u0641\u062d \u064a\u062d\u062a\u0627\u062c \u062a\u062d\u0642\u0642\u064b\u0627 \u0645\u0646\u0641\u0635\u0644\u064b\u0627"})
        else:
            executable = next((item for item in EXECUTABLES.get(name, ()) if shutil.which(item)), None)
            rows.append({"tool": name, "status": "available" if executable else "missing",
                         "available": bool(executable),
                         "detail": TOOL_DESCRIPTIONS.get(name, executable or "\u063a\u064a\u0631 \u0645\u062b\u0628\u062a")})
    return {"source": "local_PATH_and_Python_package_metadata", "commands_launched": False,
            "available_count": sum(row["available"] for row in rows), "total_count": len(rows),
            "tools": rows}


def agent_tool_availability_context(snapshot, selected_tools, profile, *, browser_xss_profile=False):
    """Build conservative model context without promoting packages to ready tools."""
    selected = set(selected_tools)
    rows = [row for row in snapshot.get("tools", [])
            if isinstance(row, dict) and row.get("tool") in selected]
    executable_on_path = sorted(row["tool"] for row in rows if row.get("status") == "available")
    prerequisite_present = sorted(row["tool"] for row in rows
                                  if row.get("available") is True and row.get("status") != "available")
    workflow_eligible = (browser_xss_profile and "browser-xss-auth" in selected
                         and "browser-xss" in prerequisite_present)
    workflow_unverified = ["browser-xss-auth"] if workflow_eligible else []
    unverified = sorted(row["tool"] for row in rows
                        if row.get("status") != "available" and row.get("tool") not in workflow_unverified)
    return {
        "selected_profile": profile,
        "selected_tools": sorted(selected),
        "executable_on_path": executable_on_path,
        "prerequisite_present_but_unverified": prerequisite_present,
        "workflow_eligible_but_runtime_unverified": workflow_unverified,
        "unavailable_or_unverified": unverified,
        "basis": "PATH and Python package metadata only; commands and browsers are not launched",
    }
