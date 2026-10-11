# HackTheBox — Principal

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 24.04)  
**IP:** 10.129.244.220  
**Hostname:** principal.htb  
**Date:** 11 March 2026  
**Author:** Pho3o  
**Machine Author:** ippsec  

---

## Executive Summary

Principal is a Medium Linux box themed around **misplaced cryptographic trust**. The foothold abuses **CVE-2026-29000**, an authentication bypass in `pac4j-jwt` 6.0.3 where a `PlainJWT` (`alg: none`) wrapped inside a valid JWE envelope skips signature verification entirely. With a forged admin token, we access the corporate dashboard, extract the SSH credential for `svc-deploy`, and pivot to the host. Privilege escalation abuses an **SSH CA misconfiguration** — `TrustedUserCAKeys` set without an `AuthorizedPrincipalsFile`, and a world-readable CA private key — allowing us to forge a certificate with `root` as the principal.

Both stages exploit the **same class of flaw**: a system that verifies the cryptographic envelope but never validates the identity claim inside it.

---

## Attack Chain

| # | Action | Result |
|---|--------|--------|
| 1 | Nmap | SSH 22, Jetty 8080, `pac4j-jwt/6.0.3` |
| 2 | `/api/auth/jwks` | Server's RSA **encryption** public key |
| 3 | **CVE-2026-29000** | PlainJWT (`alg: none`) inside valid JWE → signature check skipped |
| 4 | Forged token | Admin dashboard access |
| 5 | Users + Settings | Usernames + `encryptionKey` |
| 6 | Password spray | `svc-deploy` reuses the secret |
| 7 | `/opt/principal/ssh/` | CA private key readable by `deployers` |
| 8 | `sshd_config` | `TrustedUserCAKeys` without `AuthorizedPrincipalsFile` |
| 9 | Cert forgery | Sign pubkey with `-n root` → SSH as root |

---

## Flags

| Flag | Value |
|------|-------|
| user | `45097113d8507be243324b7894058926` |
| root | *(see notes.md)* |

---

## Skills Practiced

- pac4j-jwt authentication bypass (CVE-2026-29000)
- JWT/JWE structure and `alg: none` exploitation
- Browser session storage manipulation
- Password spraying with NetExec
- SSH Certificate Authority forgery (`ssh-keygen -s`)
- Recognizing shared root-cause patterns across crypto layers

---

## Files

- [`notes.md`](notes.md) — Full step-by-step walkthrough
- [`scripts/jwt.py`](scripts/jwt.py) — CVE-2026-29000 token forgery
- [`scripts/spray.sh`](scripts/spray.sh) — Password spray
- [`scripts/privesc.sh`](scripts/privesc.sh) — SSH CA cert forgery

---

## Root Cause

Both privilege stages are **the same failure mode** in different layers:

| Layer | Envelope verified | Identity claim ignored |
|-------|-------------------|------------------------|
| Web (JWT) | JWE decryption succeeds | Inner JWT is unsigned (`alg: none`) — no signature check |
| OS (SSH)  | Cert signature by trusted CA | Principal claim — attacker picks `root`, no `AuthorizedPrincipalsFile` |

**Envelope ≠ Identity.** Cryptographic hygiene that verifies *who signed* but not *who the token claims to be* provides no security at all.

---

## Remediation

### Web (CVE-2026-29000)

- Upgrade `pac4j-jwt` past the vulnerable 6.0.3 release
- Reject `alg: none` unconditionally. Enforce an `alg` allow-list (`RS256`, `ES256`, etc.)
- Fail closed when inner token parsing fails — never skip signature verification
- Add regression tests for JWE-wrapped unsigned JWTs

### OS (SSH CA)

- Add `AuthorizedPrincipalsFile` to restrict which principals map to which users:


- Remove world/group-readable access from the CA private key
- Audit `PermitRootLogin`: `prohibit-password` still permits cert-based root login
- Consider an HSM or agent to protect CA keys

---

*Both bugs are the same bug wearing different hats: a system that trusts the wrapper without ever reading the letter inside.*