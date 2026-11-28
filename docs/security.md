# Security model

What Keyora protects, how, and where its limits are. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

> Keyora has not been independently audited. This document describes the design and
> what the test suite checks; it is not a certification.

## What is stored, and how

| Secret | At rest | Notes |
|---|---|---|
| User passwords | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt | Self-describing format; hashes are upgraded on the next login when the work factor is raised. |
| Refresh tokens | SHA-256 | 256 bits of randomness, so a fast hash is sufficient and lookups stay cheap. |
| Email-verification and reset tokens | SHA-256 | Single use, expiring. |
| Client secrets | SHA-256 | 256 random bits, shown once at creation or rotation. |
| Root admin key | Not stored; read from the environment | Compared by hash in constant time. |
| Signing keys | PEM files, mode `0600`, in `KEYORA_KEYS_DIR` | Not encrypted at rest; protect the directory. |
| Access tokens | Not stored | |

A copy of the database therefore yields no usable credential: no password, no live
token, no client secret. It does yield personal data (emails, names, IP addresses in
sessions and audit events), so it still needs protecting.

### Why PBKDF2 and not Argon2 or bcrypt

The core uses only the Go standard library, and PBKDF2 is the password KDF it
provides. At the OWASP-recommended 600,000 iterations of HMAC-SHA256 it is an accepted
choice (and FIPS-approved), but it is not memory-hard: against GPU or ASIC attackers
Argon2id gives more protection per unit of login latency. This is a deliberate
trade-off of the zero-dependency rule, not an oversight. The hash format is versioned
so a memory-hard KDF can be added later without a forced password reset.

## Tokens

- **RS256 only.** The verifier rejects every other `alg`, including `none` and HMAC,
  before looking at a key — the algorithm-confusion attack has nothing to grab.
- **Signature first.** Claims are parsed only after the signature verifies.
- **Strict parsing.** Exactly three segments, strict unpadded base64url, a 16 KiB size
  cap. The parser is fuzzed.
- **`exp` is mandatory**; a token without one is rejected.
- **Keys of at least 2048 bits**, enforced when loading, generating and reading JWKS.
- **Audience-bound.** `aud` is the application's `client_id`. The `guard` package
  refuses to be constructed without an expected audience.
- **Refresh tokens rotate and are single use**, decided by one atomic database update.
  Reuse revokes the session.
- **Revocation.** Keyora's own endpoints and introspection check the session, user and
  tenant on every call. Offline verifiers learn of a revocation when the token expires.

## OAuth 2.0 authorization code flow

Built to the current best practice (RFC 9700, the OAuth 2.0 Security BCP) rather than
the 2012 baseline:

| Measure | Detail |
|---|---|
| PKCE is mandatory | For every application, confidential ones included. Only `S256`; `plain` is refused. |
| Exact redirect matching | `redirect_uri` must equal a registered URI character for character. No wildcards, no prefix matching. On a mismatch Keyora shows an error and does not redirect, so it cannot be used as an open redirector. |
| Codes are single use | One atomic database update decides the winner among concurrent redemptions. |
| Replay revokes | A code presented twice revokes the session and tokens issued from it. |
| Short lifetime | 60 seconds. |
| Hashed at rest | Only the SHA-256 of a code is stored. |
| Bound to the client | A code is redeemable only by the application it was issued to, with the same `redirect_uri`. |
| One failure, no retries | A wrong verifier or redirect URI spends the code. Every failure answers `invalid_grant` without saying which check failed. |
| No implicit flow | `response_type=token` is rejected; tokens never appear in a URL. |
| Issuer in the response | The redirect carries `iss` (RFC 9207) so clients can detect mix-up attacks. |
| No page, no cookie, no redirect | Keyora serves no pages and never redirects a browser. The code is requested with a JSON call that reads and sets no cookie, so there is no ambient credential for another site to ride on, and an HTML form on another site cannot produce the request (`Content-Type` must be `application/json`). |
| Browser origin | A browser may request a code only from an origin in the application's `allowed_origins`. |
| Same defences as login | The authorization request shares the per-IP rate limit and the account lockout with the login API, and does not reveal whether the email or the password was wrong. |

ID tokens are marked `token_use: id` and are refused as access tokens by Keyora and by
the `guard` package; other verifiers should check that claim.

Limits to know: there is no consent screen (every application in a tenant is
first-party) and no browser single sign-on yet, so each application's flow asks for the
password.

## Request handling

| Defence | Detail |
|---|---|
| Rate limiting | Per-IP token bucket on `/api/v1/auth/*` and `/api/v1/oauth/*`. |
| Account lockout | After N consecutive failures, for a fixed period. |
| Enumeration resistance | Unknown user and wrong password give the same response, and both cost one PBKDF2 computation. Forgot-password and resend-verification always answer `202`, with email sent in the background. |
| Input | Strict JSON (unknown fields rejected), 1 MiB body limit, per-field validation, control characters refused. |
| SQL injection | Every value is a bound parameter; no user input is concatenated into SQL. `LIKE` wildcards in filters are escaped. |
| Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, restrictive CSP, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and HSTS when the issuer is `https`. |
| CORS | Exact-match origin allow-list; credentials mode never enabled. Public applications are also checked server-side against their allowed origins. |
| CSRF | The JSON API uses no cookies: tokens travel in the `Authorization` header, which browsers do not attach automatically. Keyora sets no cookies anywhere. |
| Error bodies | Internal errors are logged with the request ID and reported as an opaque `internal_error`. |
| Logs | Never contain passwords, tokens or secrets — except the development mailer (below). |
| Timeouts | Read, header, write and idle timeouts on the server; header size capped. |

## Tenant isolation

Enforced in storage, in tokens and in the management API, as described in
[architecture.md](architecture.md#multi-tenancy). The test suite attacks each layer
separately: a tenant administrator of A against tenant B's paths (expects `403`),
tenant B's IDs under tenant A's path (expects `404`), cross-tenant role assignment,
cross-tenant introspection and refresh.

## Audit trail

Security-relevant events are recorded per tenant with actor, target, IP address, user
agent and request ID: sign-ins and failures, lockouts, refreshes, reuse detection,
logouts, password and email changes, and every administrative change. Read them at
`GET /api/v1/tenants/{id}/audit-events`.

A failure to write an audit event is logged but does not fail the operation, so the
trail is best-effort rather than transactional.

## Known trade-offs

These are decisions, with their cost stated.

- **Lockout can be used to lock someone out.** Anyone who knows an email address can
  lock that account by failing repeatedly. Lockouts expire on their own, are audited,
  and can be cleared by an administrator. The alternative — no per-account limit —
  leaves accounts open to distributed guessing.
- **A locked or disabled account is acknowledged.** `account_locked` reveals that the
  address has an account; `account_disabled` is only shown after a correct password.
  Registration necessarily reveals whether an address is taken.
- **Roles in tokens are a snapshot.** A removed role keeps working offline until the
  next refresh. Shorten the access-token lifetime, or introspect.
- **Refresh reuse detection has false positives.** A client that retries a refresh
  after a lost response is indistinguishable from an attacker and loses its session.
- **The rate limiter is per process and in memory.** With several instances the
  effective limit is multiplied; it also resets on restart. Add a shared limit at the
  proxy for stricter control.
- **`/metrics` is unauthenticated.** Restrict it at the proxy or disable it.
- **The development mailer logs tokens.** `KEYORA_MAILER=log` writes verification and
  reset tokens to the log so the flows can be exercised without SMTP. Keyora warns at
  startup; never use it in production.
- **The root admin key is a single shared secret** with no expiry and no per-person
  attribution. Use tenant administrators for routine work.
- **No MFA yet.** A password is the only factor.

## Tutorial compatibility mode

`KEYORA_LEGACY_TUTORIAL_API=true` serves the original tutorial's challenge-response
login. Its stored verifiers are password-equivalent — a copy of the
`legacy_credentials` table is enough to log in as those users — so the statement above
that a database copy yields no usable credential does **not** hold for accounts created
through it. It is off by default, warns at startup, and is for migration only. See
[legacy-tutorial-api.md](legacy-tutorial-api.md).

## Hardening checklist

- [ ] Leave `KEYORA_LEGACY_TUTORIAL_API` off, or turn it off as soon as migration is done.
- [ ] Serve Keyora only over HTTPS; set `KEYORA_ISSUER` to the `https://` URL.
- [ ] Set `KEYORA_ADMIN_KEY` from a secret manager; rotate it by restarting with a new value.
- [ ] `KEYORA_MAILER=smtp`.
- [ ] Use PostgreSQL with TLS (`sslmode=verify-full`) and a dedicated database user.
- [ ] Mount `KEYORA_KEYS_DIR` from a volume only Keyora can read; back it up.
- [ ] Set `KEYORA_TRUST_PROXY_HEADERS=true` **only** behind a proxy that overwrites
      `X-Forwarded-For`; otherwise leave it `false`.
- [ ] Block or restrict `/metrics`.
- [ ] Keep access-token lifetimes short (the default is 15 minutes).
- [ ] Ship logs somewhere durable and alert on `token.reuse_detected` and `user.locked`.
- [ ] Give each application its own `client_id`; do not share secrets between services.
