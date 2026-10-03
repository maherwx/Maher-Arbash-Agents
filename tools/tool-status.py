#!/usr/bin/env python3
import shutil

TOOLS = [
    "subfinder", "httpx", "dnsx", "naabu", "katana", "nuclei", "tlsx", "alterx",
    "assetfinder", "waybackurls", "gau", "hakrawler", "dalfox", "nmap", "ffuf",
    "gobuster", "whatweb", "wafw00f", "nikto",
]

print(f"{'TOOL':20} STATUS")
print(f"{'-'*20} {'-'*10}")
missing = []
for tool in TOOLS:
    ok = shutil.which(tool) is not None
    print(f"{tool:20} {'OK' if ok else 'MISSING'}")
    if not ok:
        missing.append(tool)
print(f"\nInstalled: {len(TOOLS)-len(missing)}/{len(TOOLS)}")
if missing:
    print("Missing:", ", ".join(missing))
