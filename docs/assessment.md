# Origins: assessment of the auth tutorial

Keyora grew out of a three-part Go tutorial
([`go-projects/projects/auth-tutorial`](https://github.com/rabbicse/go-projects/tree/main/projects/auth-tutorial)):
`part-login`, `part-oauth` and `part-jwt`. This document records what that code did,
what was carried into Keyora, what was replaced, and why. `part-jwt` is the most
complete stage, so the assessment is of that one.

## What the tutorial implements

Two Gin services with in-memory storage:

- **authorization-service** — user registration, a challenge–response login, an OAuth
  2.0 authorization-code endpoint pair (`/authorize`, `/token`), RS256 access and ID
  tokens, opaque refresh tokens with rotation, token introspection, a JWKS endpoint and
  an OpenID discovery document. Layered as `domain / application / infrastructure /
  interfaces`.
- **resource-service** — a protected endpoint that validates tokens, either by calling
  introspection or by verifying the JWT against the JWKS.

Dependencies: Gin, `golang-jwt/jwt`, `lestrrat-go/jwx`, `google/uuid`,
`golang.org/x/crypto` (Argon2).

Tests: five files under `tests/`. They are end-to-end tests that expect a server
already running on `localhost:8080`; with no server they fail at the first request
(`connection refused`). There are no unit tests.

## What was kept

| Tutorial | In Keyora | Notes |
|---|---|---|
| Layering: domain, application, infrastructure, HTTP | `internal/domain`, `service`, `store`, `httpapi` | Same separation, fewer packages and interfaces. |
| Key ring: directory of PEM files, file name is the `kid`, newest key signs, all keys published | `internal/security/keys.go` | Same design. Keys the tutorial's `keygen` wrote (PKCS#1) still load; a test covers it. |
| RS256 access tokens with `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` | `jwt` package, `service/auth.go` | Same claims, plus `sid`, `tid`, `roles`, `permissions`. |
| JWKS endpoint at `/.well-known/jwks.json` | Same path | |
| Opaque refresh tokens with rotation | `service.Refresh` | Now hashed at rest, atomic, with reuse detection. |
| Introspection for resource servers | `POST /api/v1/auth/introspect` | Now checks live session and user state. |
| Clock injection (`clock func() time.Time`) | `service.Options.Clock` | Used throughout, so expiry is testable. |
| Atomic single-use consumption (`AuthCodeRepository.Consume`) | `ConsumeAuthorizationCode`, `ConsumeRefreshToken`, `ConsumeVerificationToken` | The same idea, now one conditional `UPDATE`, applied to every single-use token. |
| OAuth 2.0 authorization code flow (`/authorize`, `/token`), exact redirect-URI match, 5-minute codes | `/api/v1/oauth/authorize`, `/api/v1/oauth/token` | Kept and hardened: PKCE, hashed codes, 60-second lifetime, replay revokes the session. See finding 6. |
| Confidential vs public clients, redirect URIs, grant types on the client model | `domain.Application` | |
| Constant-time secret comparison | `security.ConstantTimeEqual` | |
| Resource-server middleware, both styles | `guard` package; every example has `/me` and `/me/live` | |

## Security problems found

These are the reasons code was replaced rather than moved. Severity is for a real
deployment; as teaching code some of these are understandable.

| # | Finding | Where | Severity | What Keyora does |
|---|---|---|---|---|
| 1 | **The stored password verifier is password-equivalent.** The client derives `Argon2(password, salt)` and registers it; login proves knowledge of that verifier with an HMAC over a challenge. The server stores the verifier as is, so anyone who reads the user table can compute valid login proofs without knowing any password. | `login_service.go`, `user_registration.go` | Critical | Passwords are sent over TLS and hashed server-side with salted PBKDF2-HMAC-SHA256. A database leak yields only slow hashes. |
| 2 | **Secrets are written to the log**: password verifier, salt, challenge, expected proof, the full user struct, refresh tokens, authorization codes. | `login_service.go`, `token_service.go`, handlers | Critical | No credential or token is ever logged. The one deliberate exception, the development mailer, is labelled and warned about at startup. |
| 3 | **Client secrets stored and compared in plaintext**; a hard-coded client `client-123` / `secret`; introspection guarded by hard-coded `resource-server` / `secret`. | `main.go`, `introspect_handler.go` | High | Secrets are 256-bit random values, shown once, stored as SHA-256 hashes. Nothing is hard-coded. |
| 4 | **User enumeration.** `/login/challenge` answers `401 invalid user` for unknown usernames and returns the salt for known ones. | `login_handler.go` | Medium | Unknown user and wrong password are indistinguishable in response and in timing; password-reset and verification requests answer identically either way. |
| 5 | **No brute-force protection, rate limiting or lockout.** | — | High | Per-IP rate limiting on credential endpoints and per-account lockout. |
| 6 | **Authorization code flow without PKCE**, and the redirect is built by string concatenation without URL-encoding `state`. The login step also lived outside the browser, so the "authenticated user" at `/authorize` was a bearer token rather than someone at a sign-in page. | `oauth_handler.go` | High | Rebuilt: PKCE with S256 is mandatory for every client, the redirect is built with `net/url`, and Keyora hosts the sign-in page. |
| 7 | **Login tokens are never consumed.** `MarkUsed` exists but nothing calls it; the token is valid for its full two minutes for any number of `/authorize` calls. | `login_token_service.go` | Medium | Every single-use token is consumed atomically. |
| 8 | **Refresh rotation is not atomic and has no reuse detection.** `Get` then `Delete` are separate steps, so two concurrent refreshes with one token can both succeed; a replayed token is just "invalid". Rotation also drops the token's scopes. | `token_issuer.go`, `refresh_store.go` | High | One conditional `UPDATE` decides the winner; a replay revokes the session. Tested with concurrent callers on every backend. |
| 9 | **Tokens stored in plaintext** (access, refresh and ID tokens as map keys/values). | `memory/` | Medium | Access tokens are not stored at all; refresh and verification tokens are stored as hashes. |
| 10 | **The resource server does not validate issuer or audience.** `jwt.Parse(..., WithKeySet, WithValidate)` checks signature and time only, so a token issued to any client is accepted by every resource server. | `jwt_token_validator.go` | High | `guard` requires both an issuer and an audience and refuses to be constructed without them. |
| 11 | **ID tokens always assert `email_verified: true`**, and registration sets `IsVerified: true` unconditionally. | `token_issuer.go`, `user_registration.go` | Medium | Verification is a real flow; the flag is only set by confirming a token (or by an administrator). |
| 12 | **Issuer hard-coded** to `http://localhost:8080`; token lifetimes hard-coded. | `main.go`, `token_issuer.go` | Medium | Configuration, validated at startup. |
| 13 | **No input validation**: empty usernames, any email string, unbounded body sizes. Registration checks username uniqueness, then the store checks email, with a race between them. | handlers | Medium | Strict JSON decoding, size limits, field validation, uniqueness enforced by database constraints. |
| 14 | **Key generation can overwrite**: the file is opened without `O_EXCL` after a separate existence check. | `rsa_generator.go` | Low | `O_EXCL`; a test proves an existing key file is never replaced. |
| 15 | **Possible nil dereference** in `MarkUsed` for an unknown ID; `rand.Read` errors ignored. | `memory/*.go`, `crypto_utils.go` | Low | Not applicable to the new code. |

Not a vulnerability, but worth knowing: the tutorial's `secrets/*.pem` files are
correctly git-ignored and are not in the repository's history.

## Architectural limits

- **Storage is in-memory only**, so nothing survives a restart, and there is no
  migration story.
- **No tenants, no roles, no permissions, no sessions, no audit trail.** One global
  user pool; `AccessClaims.Roles` exists but is never filled.
- **Gin is imported by handlers and middleware**, so the HTTP layer cannot be reused
  without it.
- **Too many small packages and one-method interfaces** for the amount of logic
  (65 files for about 2,500 lines), which made the flow hard to follow.
- **Two parallel error vocabularies** (`domain/errors.go` and `application/errors.go`)
  and errors returned to clients as raw `err.Error()` strings.
- **No graceful shutdown, health checks, structured logs or metrics.**

## What was deliberately not carried over (yet)

| Tutorial feature | Status in Keyora | Reason |
|---|---|---|
| Challenge–response login | Replaced as the default; kept as an opt-in compatibility mode | Finding 1. A sound version of the idea is an augmented PAKE such as OPAQUE or SRP; that is a larger design than this release and is not on the near roadmap. |
| ID tokens and `/.well-known/openid-configuration` | Kept, reworked | ID tokens are issued for the `openid` scope with `nonce` and a real `email_verified`; there is a userinfo endpoint; the discovery document lists only what exists. |
| Gin in the server | Removed from the core | Available as an optional adapter module for applications that use Gin. |

Clients written for the tutorial can keep working: see
[legacy-tutorial-api.md](legacy-tutorial-api.md).

## Compatibility with the tutorial

Keyora's own API is new: paths, request bodies and the login protocol all changed,
because the login protocol itself was the main problem.

The tutorial's API is still available as an **opt-in compatibility mode**
(`KEYORA_LEGACY_TUTORIAL_API=true`), which serves the original endpoints and
challenge-response login. The tutorial's own test suite gives the same results against
Keyora in that mode as against the original server. It exists for migration; the
steps are in [legacy-tutorial-api.md](legacy-tutorial-api.md).

An existing `secrets/keys` directory can be used as `KEYORA_KEYS_DIR` unchanged.
