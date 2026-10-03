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
python -m pip install -e . >/dev/null

case "${1:-run}" in
  doctor)
    exec maher-bounty doctor
    ;;
  install-tools)
    chmod +x tools/install-kali-recon.sh
    exec ./tools/install-kali-recon.sh
    ;;
  recon)
    DOMAIN="${2:?Usage: ./run.sh recon example.com}"
    chmod +x tools/recon-passive.sh
    ./tools/recon-passive.sh "$DOMAIN"
    maher-bounty inventory "results/$DOMAIN"
    echo "[+] Recon + normalized inventory complete: results/$DOMAIN/inventory.json"
    ;;
  run)
    SCOPE="${2:-examples/scope.yaml}"
    RULES="${3:-examples/rules.yaml}"
    OUT="${4:-reports}"
    INVENTORY="${MAHER_INVENTORY:-}"
    if [ -n "$INVENTORY" ]; then
      exec maher-bounty run --scope "$SCOPE" --rules "$RULES" --out "$OUT" --inventory "$INVENTORY"
    fi
    exec maher-bounty run --scope "$SCOPE" --rules "$RULES" --out "$OUT"
    ;;
  *)
    echo "Maher Bounty Agents"
    echo "  ./run.sh doctor"
    echo "  ./run.sh install-tools"
    echo "  ./run.sh recon example.com"
    echo "  MAHER_INVENTORY=results/example.com/inventory.json ./run.sh run examples/scope.yaml examples/rules.yaml reports"
    exit 2
    ;;
esac
