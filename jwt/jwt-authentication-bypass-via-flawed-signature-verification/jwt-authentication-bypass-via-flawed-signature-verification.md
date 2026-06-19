# JWT Authentication Bypass via Flawed Signature Verification

**Category:** Broken Authentication  
**Difficulty:** ⭐ (Apprentice)  
**Severity:** 🔴 Critical  
**OWASP Top 10:** A07:2021 – Identification and Authentication Failures

---

## Description

The application uses JWT tokens for session management but accepts tokens with an **empty or removed signature**. This means an attacker can modify the JWT payload — for example, changing the `sub` claim from a regular user to `administrator` — then strip the signature entirely, and the server will still accept the forged token as valid.

Unlike the "unverified signature" variant where the signature is simply ignored, this lab's flaw is that the server accepts a structurally valid JWT even when the signature component is blank — indicating the verification logic is either broken or conditionally skipped.

---

## Discovery Process

### Step 1 — Login as regular user

Logged in using the credentials `wiener:peter` through the standard login form.

> 📸 `screenshots/01-login.png`

### Step 2 — Access `/admin` — blocked

Attempted to navigate directly to `/admin`. The server returned `HTTP/2 401 Unauthorized`, confirming the endpoint exists but requires admin privileges.

> 📸 `screenshots/02-admin-401.png`

### Step 3 — Inspect the JWT in Burp Suite

Intercepted the request and examined the session cookie using Burp's JWT Editor extension. Decoded the token and identified the payload:

```json
{
  "iss": "portswigger",
  "exp": 1781848963,
  "sub": "wiener"
}
```

The header showed `"alg": "RS256"` with a `kid` value — indicating asymmetric signing. The response returned `HTTP/2 401 Unauthorized` with the original token, confirming access is restricted.

> 📸 `screenshots/03-jwt-decoded.png`

---

## Exploitation

### Step 4 — Modify the payload and remove the signature

In Burp's JWT Editor:

1. Changed `"sub": "wiener"` to `"sub": "administrator"` in the payload
2. Deleted the signature value entirely, leaving only the header and payload
3. Clicked **"Send to Tokens"** and forwarded the modified token via Repeater

### Step 5 — Access `/admin` — success

Sent `GET /admin` with the forged token. The server returned `HTTP/2 200 OK` and rendered the admin panel, showing users `wiener` and `carlos` with delete options — confirming full admin access was granted.

> 📸 `screenshots/04-admin-panel.png`

### Step 6 — Delete user `carlos`

Sent the following request with the forged token:

```http
GET /admin/delete?username=carlos HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt-with-sub:administrator]
```

**Response:**

```http
HTTP/2 302 Found
Location: /admin
Content-Length: 0
```

The server accepted the request and redirected back to `/admin` — confirming `carlos` was successfully deleted.

### Step 7 — Lab solved

> 📸 `screenshots/06-solved.png`

---

## Impact

- **Full authentication bypass** — any user can impersonate any account including administrators
- **Privilege escalation** — low-privileged user gains admin access with zero credentials
- **Destructive actions** — admin functions such as deleting users are fully accessible
- **No attack complexity** — requires only a JWT editor; no key knowledge or brute-force needed
- **Unsafe HTTP method** — user deletion is triggered via `GET` request, making it vulnerable to accidental execution through browser history, cached links, or CSRF attacks

---

## Root Cause

The server's JWT verification logic is flawed — it fails to reject tokens with a missing or empty signature. A correctly implemented JWT library must validate that the signature matches the payload using the server's secret or public key. Here, that check either does not run or is bypassed when the signature field is blank.

**Vulnerable flow:**

```text
Client sends JWT (no signature) → Server decodes payload → Server trusts sub claim → ❌ No signature check
```

**Secure flow:**

```text
Client sends JWT → Server decodes payload → Server verifies signature → ✅ Only then trusts claims
```

---

## Remediation

- **Always verify the JWT signature** before trusting any claims — reject tokens with missing, empty, or invalid signatures
- Use a well-maintained JWT library (e.g., `jsonwebtoken` for Node.js, `PyJWT` for Python) and never implement verification manually
- Explicitly specify the expected algorithm on the server side — never allow the client to dictate the algorithm
- Never allow `"alg": "none"` in production
- Add integration tests that send JWTs with no signature and assert they are rejected with `401`
- Use `DELETE` HTTP method for destructive actions instead of `GET`

---

## Tools Used

- Burp Suite (Proxy & Repeater)
- Burp JWT Editor Extension

---

## References

- [PortSwigger – JWT attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 – JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP – Broken Authentication (A07:2021)](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
