#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. On Kali: sudo apt update && sudo apt install -y python3 python3-venv"
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -e .

SCOPE="${1:-examples/scope.yaml}"
RULES="${2:-examples/rules.yaml}"
maher-bounty run --scope "$SCOPE" --rules "$RULES"
