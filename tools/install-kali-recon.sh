#!/usr/bin/env bash
set -euo pipefail

# Maher Bounty Agents - Kali recon toolkit
# Installers only. Use tools only against assets explicitly allowed by your program scope.

sudo apt update
sudo apt install -y git curl wget jq python3 python3-pip python3-venv golang-go nmap whatweb wafw00f ffuf gobuster nikto

GOBIN="${HOME}/go/bin"
mkdir -p "$GOBIN"
export PATH="$PATH:$GOBIN"

install_go() {
  local pkg="$1"
  echo "[+] Installing $pkg"
  go install "$pkg"
}

# ProjectDiscovery discovery/probing/crawling stack
install_go github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go github.com/projectdiscovery/dnsx/cmd/dnsx@latest
install_go github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
install_go github.com/projectdiscovery/katana/cmd/katana@latest
install_go github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go github.com/projectdiscovery/tlsx/cmd/tlsx@latest
install_go github.com/projectdiscovery/alterx/cmd/alterx@latest

# Passive URL/archive and discovery helpers
install_go github.com/tomnomnom/assetfinder@latest
install_go github.com/tomnomnom/waybackurls@latest
install_go github.com/lc/gau/v2/cmd/gau@latest
install_go github.com/hakluke/hakrawler@latest

# Web testing helpers
install_go github.com/hahwul/dalfox/v2@latest

if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi

cat <<'EOF'

[+] Kali recon toolkit installation finished.
[+] Add Go binaries to future shells if necessary:
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc

Core tools installed:
  subfinder httpx dnsx naabu katana nuclei tlsx alterx
  assetfinder waybackurls gau hakrawler dalfox
  nmap ffuf gobuster whatweb wafw00f nikto

Keep every target within the bug-bounty program's authorized scope and rules.
EOF
