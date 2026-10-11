#!/usr/bin/env bash
# =============================================================================
# setup.sh — Prepare a fresh Kali environment for the Principal box.
#
# Creates a venv, installs dependencies, and drops the target hostname into
# /etc/hosts.
# =============================================================================

set -euo pipefail

TARGET_IP="${1:-<TARGET_IP>}"
HOSTNAME_ALIAS="${2:-principal.htb}"

# --- 1. /etc/hosts --------------------------------------------------------
if ! grep -q "$HOSTNAME_ALIAS" /etc/hosts; then
    echo "[*] Adding $HOSTNAME_ALIAS -> $TARGET_IP to /etc/hosts"
    echo "$TARGET_IP  $HOSTNAME_ALIAS" | sudo tee -a /etc/hosts >/dev/null
else
    echo "[*] $HOSTNAME_ALIAS already in /etc/hosts"
fi

# --- 2. venv + pip --------------------------------------------------------
if [[ ! -d "$HOME/venv" ]]; then
    echo "[*] Creating venv at ~/venv"
    python3 -m venv "$HOME/venv"
fi

# shellcheck disable=SC1091
source "$HOME/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet jwcrypto requests

echo "[+] Environment ready. Activate with: source ~/venv/bin/activate"
echo "[+] Then run: python3 scripts/jwt.py http://$HOSTNAME_ALIAS:8080"

# Make it executable:

# chmod +x scripts/setup.sh