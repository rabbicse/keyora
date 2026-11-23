# Tutorial compatibility and migration

Keyora grew out of the
[auth-tutorial](https://github.com/rabbicse/go-projects/tree/main/projects/auth-tutorial).
This page is for anyone who has clients written against that tutorial's API. It covers
two things:

1. **Compatibility mode** — Keyora can serve the tutorial's original endpoints, so
   existing clients keep working unchanged.
2. **Migration** — how to move those clients and their users to Keyora's own API, step
   by step.

> **Compatibility mode is off by default and is meant for migration, not for new
> work.** The tutorial's login protocol stores a *password-equivalent verifier*: anyone
> who obtains it can log in as that user without knowing the password. Keyora cannot
> fix that without changing the protocol, so it keeps the protocol only behind an
> explicit switch.

## Turning it on

1. Create a tenant and a **confidential** application whose `redirect_uris` include
   the ones your clients use (see the [README quick start](../README.md#quick-start)).
2. Start Keyora with:

   ```sh
   KEYORA_LEGACY_TUTORIAL_API=true
   KEYORA_LEGACY_TUTORIAL_CLIENT_ID=app_…     # that application's client_id
   ```

Legacy registrations and logins use that application's tenant. Keyora logs a warning
at startup while the mode is on.

The tutorial hard-coded a client `client-123` / `secret`. Keyora generates client
credentials, so update the client configuration to the generated `client_id` and
`client_secret`.

## What is served

| Tutorial endpoint | Behaviour in Keyora |
|---|---|
| `GET /health` | `{"status":"ok"}` |
| `POST /users/register` `{username, email, salt, verifier}` | `201 {id, username}`; `409` if the username or email exists |
| `POST /login/challenge` `{username}` | `200 {challenge_id, challenge, salt}` |
| `POST /login/verify` `{username, challenge_id, proof}` | `200 {login_token}`; `401 {"error":"invalid login"}` |
| `GET /authorize?response_type=code&client_id&redirect_uri&scope&state` with `Authorization: Bearer <login_token>` | `302` to `redirect_uri?code=…&state=…` |
| `POST /token` (form) `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `client_secret` | `200 {access_token, refresh_token, token_type, expires_in, scope, id_token}` |
| `POST /token` (form) `grant_type=refresh_token`, `refresh_token` | `200` with rotated tokens |
| `POST /oauth/introspect` `{token}` with HTTP Basic client credentials | `200 {active, sub, client_id, exp}` |
| `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration` | Always served, compatibility mode or not |

Encodings are unchanged: `salt`, `verifier`, `challenge` and `proof` are base64url
without padding; `verifier = Argon2id(password, salt, t=1, m=64 MiB, p=4, 32 bytes)`
is computed by the client; `proof = HMAC-SHA256(verifier, challenge)`. Errors are the
tutorial's flat `{"error": "…"}`.

### Verified against the tutorial's own tests

The tutorial's test suite (`part-jwt/authorization-service/tests`), run unmodified
against Keyora in compatibility mode together with the tutorial's own resource
service, gives **the same result as against the original tutorial server**:

| Tutorial test | Original server | Keyora |
|---|---|---|
| `Test_Full_Identity_Flow` (register → challenge → verify → authorize → token → protected resource → refresh) | pass | pass |
| `Test_Registration_Flow` | pass | pass |
| `Test_Login_Flow` | fail | fail |
| `Test_OAuth2_Authorization_Code_Flow` | fail | fail |
| `Test_OAuth_OIDC_EndToEnd` | fail | fail |

The three failures are faults in those tests, not in either server: two call
`/authorize` without the login token the tutorial's own middleware requires, and one
re-registers the fixed user `alice` that an earlier test already created.

## Deliberate differences

Where matching the tutorial exactly would have meant keeping a vulnerability, Keyora
differs. A well-behaved client does not notice any of these.

| Tutorial | Keyora | Why |
|---|---|---|
| `/login/challenge` answers `401 invalid user` for unknown usernames | Answers `200` with a stable fake salt and an unanswerable challenge | Stops username enumeration. The login still fails at `/login/verify`. |
| A login token can be used any number of times for two minutes | Single use | A leaked token cannot be replayed. |
| A challenge can be retried | One attempt per challenge | Limits guessing. |
| No limit on failed logins | Account lockout and per-IP rate limiting, shared with the rest of Keyora | Brute-force protection. |
| Verifier, salt, challenge, expected proof and tokens are written to the log | Nothing secret is logged | — |
| Introspection accepts the hard-coded pair `resource-server` / `secret` | Requires a real confidential application's credentials | No built-in credentials. |
| Authorization codes last 5 minutes | 60 seconds, single use; a replay revokes the session | — |
| Refresh rotation could be raced, and dropped the token's scope | Atomic, with reuse detection | — |
| ID token always says `email_verified: true` | Reports the real state | — |
| Everything in memory, lost on restart | Users and verifiers are stored in the database | — |
| `redirect_uri` built by string concatenation | Built with URL encoding | `state` values with `&` or `=` survive. |

Two limits of compatibility mode itself:

- **Challenges and login tokens are kept in process memory** (two-minute lifetime), as
  in the tutorial. With several Keyora instances, a login's three requests must reach
  the same instance; use sticky routing for these paths or run one instance during
  migration.
- **Legacy codes carry no PKCE**, so they are issued only to confidential applications
  and redeemed only at `/token` with the client secret. They cannot be redeemed at
  `/api/v1/oauth/token`, and PKCE codes cannot be redeemed at `/token`.

## Migrating to Keyora's API

The goal is to end with compatibility mode switched off. Each step can be released on
its own.

### Step 1 — Run Keyora with compatibility mode

Deploy Keyora where the tutorial server was, with the mode on, and point existing
clients at it with the new client credentials. Nothing else changes for them. Existing
tutorial users have to register again: the tutorial kept users in memory, so there is
nothing to import.

An existing `secrets/keys` directory from the tutorial can be used as `KEYORA_KEYS_DIR`
unchanged, so previously distributed public keys stay valid.

### Step 2 — Move resource servers to full token validation

The tutorial's resource server checked the signature and expiry only. Change each one
to also require the issuer and audience — see
[integration.md](integration.md#step-6-protect-endpoints) or, in Go:

```go
g, _ := guard.New(guard.Config{Issuer: "https://id.example.com", Audience: clientID})
mux.Handle("GET /protected", g.Middleware(handler))
```

Access tokens issued through the legacy endpoints are ordinary Keyora tokens, so this
works before any client changes.

### Step 3 — Give every user a real password

A legacy account has a verifier and no password. Its owner gets one through the normal
reset flow, which needs no knowledge of the old credentials:

```sh
curl -X POST https://id.example.com/api/v1/auth/password/forgot -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Content-Type: application/json' -d '{"email": "ada@example.com"}'
# the user receives a token by email, then:
curl -X POST https://id.example.com/api/v1/auth/password/reset \
  -H 'Content-Type: application/json' -d '{"token": "kyp_…", "new_password": "…"}'
```

After that the account works with both the legacy login and the new one. Prompt users
to do this at their next sign-in.

### Step 4 — Switch clients to the new sign-in

Replace the three legacy calls (`/login/challenge`, `/login/verify`, `/authorize`)
with one of:

| If the client is… | Use | Calls |
|---|---|---|
| A browser or mobile app | Authorization code flow with PKCE | `GET /api/v1/oauth/authorize` → `POST /api/v1/oauth/token` |
| A backend with its own login form | Direct login | `POST /api/v1/auth/login` |

| Legacy call | Replacement |
|---|---|
| `POST /users/register` with salt + verifier | `POST /api/v1/auth/register` with email + password (over TLS). No client-side Argon2. |
| `/login/challenge` + `/login/verify` + `GET /authorize` | The browser is sent to `/api/v1/oauth/authorize` with a PKCE challenge; Keyora shows the sign-in page |
| `POST /token` with `client_secret` | `POST /api/v1/oauth/token` with `code_verifier` (and the secret, for confidential apps) |
| `POST /token` `grant_type=refresh_token` | `POST /api/v1/oauth/token` `grant_type=refresh_token`, or `POST /api/v1/auth/refresh` |
| `POST /oauth/introspect` | `POST /api/v1/auth/introspect` |
| `id_token` from `/token` | Request `scope=openid email profile`; verify `nonce` |

Worked examples: [authentication.md](authentication.md#authorization-code-flow-with-pkce)
and [`examples/golang/pkce`](../examples/golang/pkce).

### Step 5 — Switch compatibility mode off

When the audit trail shows no more legacy sign-ins —

```sh
curl "https://id.example.com/api/v1/tenants/$TENANT_ID/audit-events?type=user.login.succeeded" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
# legacy sign-ins carry "metadata": {"flow": "legacy"}
```

— remove `KEYORA_LEGACY_TUTORIAL_API` and restart. The legacy paths then answer `404`.
The stored verifiers remain in the `legacy_credentials` table; delete them once you
are sure you will not switch the mode back on:

```sql
DELETE FROM legacy_credentials;
```
