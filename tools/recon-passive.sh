#!/usr/bin/env bash
set -euo pipefail

# Passive-first reconnaissance workflow.
# Usage: ./tools/recon-passive.sh example.com [output-dir]
DOMAIN="${1:?Usage: $0 domain [output-dir]}"
OUT="${2:-results/${DOMAIN}}"
mkdir -p "$OUT"

run_if() {
  local tool="$1"; shift
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[+] $tool"
    "$tool" "$@" || true
  else
    echo "[-] $tool not installed"
  fi
}

# Passive subdomain collection
run_if subfinder -silent -d "$DOMAIN" -o "$OUT/subfinder.txt"
run_if assetfinder --subs-only "$DOMAIN" > "$OUT/assetfinder.txt"
cat "$OUT"/subfinder.txt "$OUT"/assetfinder.txt 2>/dev/null | sed '/^$/d' | sort -u > "$OUT/subdomains.txt"

# Archive URL collection
run_if waybackurls "$DOMAIN" > "$OUT/wayback.txt"
run_if gau --subs "$DOMAIN" > "$OUT/gau.txt"
cat "$OUT"/wayback.txt "$OUT"/gau.txt 2>/dev/null | sed '/^$/d' | sort -u > "$OUT/archive-urls.txt"

# Non-invasive HTTP metadata for discovered hosts
if command -v httpx >/dev/null 2>&1 && [ -s "$OUT/subdomains.txt" ]; then
  httpx -silent -l "$OUT/subdomains.txt" -status-code -title -tech-detect -json -o "$OUT/httpx.jsonl" || true
fi

printf '[+] Results written to %s\n' "$OUT"
