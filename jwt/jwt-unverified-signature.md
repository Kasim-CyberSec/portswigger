# JWT Authentication Bypass via Unverified Signature

**Category:** Broken Authentication  
**Difficulty:** ⭐ (Apprentice)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

The application uses JWT tokens for session management but **never verifies the token's signature**. This means an attacker can modify the JWT payload — for example, changing the `sub` claim from a regular user to `administrator` — without knowing the secret key, and the server will accept the forged token as valid.

---

## Discovery Process

## Step 1 — Login as regular user**

Logged in using the credentials `wiener:peter` through the standard login form.

> 📸 `screenshots/01-login.png`

**Step 2 — Access `/admin` — blocked**

Attempted to navigate directly to `/admin`. The server returned `HTTP/2 401 Unauthorized`, confirming the endpoint exists but requires admin privileges.

> 📸 `screenshots/02-admin-401.png`

## Step 3 — Inspect the JWT in Burp Suite**

Intercepted the `GET /my-account` request and examined the session cookie. Using Burp's JWT Editor extension, decoded the token and identified the payload:

```json
{
  "iss": "portswigger",
  "exp": 1781841717,
  "sub": "wiener"
}
```

The header showed `"alg": "RS256"` with a `kid` value — indicating asymmetric signing — but the server never validates the signature.

> 📸 `screenshots/03-jwt-decoded.png`

---

## Exploitation

### Step 4 — Modify the JWT payload

In Burp's JWT Editor, changed the `sub` claim from `"wiener"` to `"administrator"` without modifying or resigning the token.

**Modified payload:**

```json
{
  "iss": "portswigger",
  "exp": 1781841717,
  "sub": "administrator"
}
```

Clicked **"Send to Tokens"** and forwarded the request to Repeater with the modified token.

> 📸 `screenshots/04-jwt-modified.png`

**Step 5 — Access `/admin` — success**

Sent `GET /admin` with the forged token. The server returned `HTTP/2 200 OK` and rendered the admin panel, listing users `wiener` and `carlos` with delete options.

**Step 6 — Delete user `carlos`**

Sent the request:

```http
GET /admin/delete?username=carlos HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt-with-sub:administrator]
```

**Response:**

```http
HTTP/2 302 Found
Location: /admin
```

The server accepted the request and redirected back to `/admin` — confirming `carlos` was deleted.

> 📸 `screenshots/06-delete-302.png`

## Step 7 — Lab solved**

> 📸 `screenshots/07-solved.png`

---

## Impact

- **Full authentication bypass** — any user can impersonate any account including administrators
- **Privilege escalation** — low-privileged user gains admin access with zero credentials
- **Destructive actions** — admin functions (delete users, access sensitive data) fully accessible
- **No attack complexity** — requires only a JWT editor; no brute-force or key knowledge needed
- **Unsafe HTTP method** — user deletion is triggered via `GET` request,making it vulnerable to accidental execution through browser history,cached links, or CSRF attacks

---

## Root Cause

The server accepts any JWT regardless of whether the signature is valid or matches the secret/public key. The signature verification step is either missing entirely or disabled. This violates the fundamental guarantee of JWT — that the payload cannot be tampered with without detection.

**Vulnerable flow:**

```text
Client sends JWT → Server decodes payload → Server trusts sub claim → ❌ No signature check
```

**Secure flow:**

```text
Client sends JWT → Server decodes payload → Server verifies signature → ✅ Only then trusts claims
```

---

## Remediation

- **Always verify the JWT signature** before trusting any claims in the payload
- Use a well-maintained JWT library (e.g., `jsonwebtoken` for Node.js, `PyJWT` for Python) and never implement verification manually
- Explicitly specify the allowed algorithm — never allow `"alg": "none"`
- Rotate signing keys regularly and store them securely (environment variables / secrets manager)
- Add integration tests that send JWTs with invalid or missing signatures and assert they are rejected with `401`

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- Burp JWT Editor Extension

---

## References

- [PortSwigger – JWT attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 – JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP – Broken Authentication (A07:2021)](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
