# Keyora integration examples

Each directory here is a small, runnable application that uses Keyora for sign-in and
access control. They are all the same application — a notes API — written idiomatically
in different languages, so you can read the one closest to your stack.

None of them needs Go. Keyora is reached over HTTP; the only thing an application has
to do in its own language is call a few REST endpoints and verify an RS256 JWT.

| Example | Stack | Port |
|---|---|---|
| [`golang/standard-library`](golang/standard-library) | Go `net/http` + `guard` package | 9001 |
| [`golang/gin`](golang/gin) | Go + Gin + `keyoragin` adapter | 9002 |
| [`golang/pkce`](golang/pkce) | Go web app: browser sign-in with the authorization code flow and PKCE | 9010 |
| [`typescript/express`](typescript/express) | TypeScript + Express | 9003 |
| [`typescript/node-fetch`](typescript/node-fetch) | TypeScript script, no framework | – |
| [`python/fastapi`](python/fastapi) | Python + FastAPI | 9004 |
| [`python/flask`](python/flask) | Python + Flask | 9005 |
| [`java/spring-boot`](java/spring-boot) | Java + Spring Boot | 9006 |
| [`java/plain-java`](java/plain-java) | Java 17 standard library only | – |
| [`dotnet/aspnet-core`](dotnet/aspnet-core) | C# + ASP.NET Core | 9007 |
| [`php/plain-php`](php/plain-php) | PHP, no framework | 9008 |
| [`php/laravel`](php/laravel) | PHP + Laravel | 9009 |
| [`rust/axum`](rust/axum) | Rust + axum | 9011 |
| [`ruby/sinatra`](ruby/sinatra) | Ruby + Sinatra | 9012 |

All but `golang/pkce` are APIs that follow the contract below and forward a login form
to Keyora. `golang/pkce` shows the other way to sign in: redirecting the browser to
Keyora's own sign-in page.

## What happens where

```mermaid
sequenceDiagram
    participant B as Browser / mobile app
    participant A as Your application (example)
    participant K as Keyora

    B->>A: POST /login {email, password}
    A->>K: POST /api/v1/auth/login + client_id:client_secret
    K-->>A: access_token (JWT), refresh_token
    A-->>B: tokens
    Note over A,K: once, then cached
    A->>K: GET /.well-known/jwks.json
    B->>A: GET /notes + Bearer access_token
    A->>A: verify signature, exp, iss, aud; check permission
    A-->>B: 200 notes
```

**Against Keyora** (your server calls it, with the client secret): register, login,
refresh, logout, introspection. Roles and permissions are managed there too.

**Inside your application** (no call to Keyora per request): verifying the access token
and deciding whether its roles and permissions allow the request.

The client secret stays on your server. A browser or mobile app never sees it; if you
have no server at all, register a `public` application instead and call Keyora from the
browser with the `client_id` only (see [docs/integration.md](../docs/integration.md)).

## Run an example

1. **Start Keyora** (any of the ways in the main [README](../README.md)), for example:

   ```sh
   export KEYORA_ADMIN_KEY="$(openssl rand -hex 32)"
   docker compose up -d        # or run the keyora binary
   ```

2. **Create the tenant, application, roles and permissions** the examples use:

   ```sh
   KEYORA_URL=http://localhost:8080 ./examples/setup.sh
   ```

   This writes `examples/.env` with the application's `client_id` and `client_secret`.
   Every example reads its settings from the environment, so load that file first:

   ```sh
   set -a; . examples/.env; set +a
   ```

3. **Start an example** by following the README in its directory.

4. **Check it** with the shared verification script (Python 3, no packages needed):

   ```sh
   python3 examples/verify.py http://localhost:9001
   ```

   It registers a user, signs in, calls protected endpoints, grants roles, refreshes,
   waits for a token to expire, logs out and replays a refresh token — 35 checks. It applies
   to the API examples; `golang/pkce` is driven from a browser. Add
   `--skip-expiry` to skip the 60-second wait.

## Configuration

| Variable | Meaning |
|---|---|
| `KEYORA_URL` | Where the example reaches Keyora (API calls and JWKS). |
| `KEYORA_ISSUER` | The `iss` value to require in tokens. Equals Keyora's `KEYORA_ISSUER`; defaults to `KEYORA_URL`. They differ when the example reaches Keyora on an internal address, such as from inside a container. |
| `KEYORA_CLIENT_ID` | The application's client ID. Also the `aud` value to require in tokens. |
| `KEYORA_CLIENT_SECRET` | The application's secret. Server-side only. |
| `PORT` | Port the example listens on. |

## The contract every server example implements

| Endpoint | Auth | Behaviour |
|---|---|---|
| `GET /public` | none | `200` |
| `POST /register` `{email, password, name}` | none | Forwards to Keyora. `201` with the user. |
| `POST /login` `{email, password}` | none | Forwards to Keyora. `200` with `access_token`, `refresh_token`, `expires_in`. |
| `POST /refresh` `{refresh_token}` | none | Forwards to Keyora. `200` with new tokens. |
| `POST /logout` `{refresh_token}` | none | Forwards to Keyora. `204`. |
| `GET /me` | access token, verified **locally** | `200` `{sub, email, roles, permissions}` from the token. |
| `GET /me/live` | access token, verified by **introspection** | Same shape, from Keyora's live state. |
| `GET /notes` | permission `notes:read` | `200` |
| `POST /notes` `{text}` | permission `notes:write` | `201` |
| `GET /reports` | role `editor` | `200` |

Errors are `{"error": {"code": "...", "message": "..."}}`. Keyora's own error codes are
passed through unchanged; the examples add `missing_token`, `invalid_token`,
`token_expired` (all `401`) and `forbidden` (`403`).

## Verifying a token correctly

Whatever library you use, all six checks are required:

1. The algorithm is **RS256** — pin it; never accept the algorithm named by the token.
2. The **signature** verifies against the key from the JWKS whose `kid` matches.
3. **`exp`** is in the future.
4. **`iss`** equals your Keyora issuer.
5. **`aud`** equals your application's `client_id`.
6. **`token_use`** equals `"access"`.

Skipping the audience check is the most common mistake: without it, a token issued to
any other application on the same Keyora is accepted by yours.

The `token_use` check is the one a JWT library will not do for you. An OIDC ID token
(`token_use: "id"`) is signed with the same key and has the same issuer and audience as
an access token, so the first five checks all pass. It says who signed in; it is not a
credential for your API. Refuse any token whose `token_use` is missing or not `"access"`.

## Local verification or introspection?

| | Local JWT verification | Introspection |
|---|---|---|
| Network call per request | No | Yes |
| Works while Keyora is down | Yes (with cached keys) | No |
| Sees logout / disabled user | Only when the token expires | Immediately |
| Sees role changes | On the next refresh | Immediately |

Verify locally by default and keep access tokens short-lived. Use introspection for
the few operations where acting on a just-revoked session would be unacceptable —
payments, changing credentials, administrative actions. `/me` and `/me/live` in each
example show the two side by side, and `verify.py` demonstrates the difference after
logout.
