# Keyora example: TypeScript + Express

A small notes API that uses [Keyora](../../../README.md) for sign-in and access control.
It implements the HTTP contract shared by every server example in this repository (see
[`examples/README.md`](../../README.md)) and listens on port 9003.

The application does two jobs:

- **Backend for a frontend.** `/register`, `/login`, `/refresh` and `/logout` forward to
  Keyora with the application's client secret attached.
- **Resource server.** `/me`, `/notes` and `/reports` verify the access token locally and
  check the roles and permissions inside it.

| File | Contents |
|---|---|
| [`src/app.ts`](src/app.ts) | Routes and the error handler. |
| [`src/auth.ts`](src/auth.ts) | Token verification with `jose`, and the `authenticate`, `requirePermission`, `requireRole` middleware. |
| [`src/keyora.ts`](src/keyora.ts) | The HTTP client for Keyora's REST API (uses the client secret). |
| [`src/config.ts`](src/config.ts) | Reads the environment variables. |
| [`src/errors.ts`](src/errors.ts) | The error type behind every `{"error": {...}}` response. |
| [`src/server.ts`](src/server.ts) | Entry point: loads the configuration and starts listening. |

## Prerequisites

- Node.js 20 or newer (developed and tested with Node 26) and npm.
- A running Keyora. The commands below assume `http://localhost:8080`.
- `examples/.env`, written by `examples/setup.sh`. The script creates a tenant, an
  application, the permissions `notes:read` and `notes:write`, and the roles `reader` and
  `editor`. See [`examples/README.md`](../../README.md#run-an-example).
- `curl` for the requests below, and Python 3 if you want to run `examples/verify.py`.

## Installation

```sh
cd examples/typescript/express
npm install
```

Runtime dependencies are `express` and `jose`. HTTP calls to Keyora use Node's built-in
`fetch`.

## Configuration

All settings come from environment variables. Nothing is read from a file by the
application itself, so load `examples/.env` into your shell before starting it.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KEYORA_URL` | no | `http://localhost:8080` | Where this application reaches Keyora, for API calls and for the JWKS (`$KEYORA_URL/.well-known/jwks.json`). |
| `KEYORA_ISSUER` | no | value of `KEYORA_URL` | The `iss` claim to require in access tokens. Must equal the `KEYORA_ISSUER` that Keyora itself runs with. Set it when the application reaches Keyora on a different address than the public one, for example from inside a container. |
| `KEYORA_CLIENT_ID` | yes | | The application's client ID. Also the `aud` claim to require in access tokens. |
| `KEYORA_CLIENT_SECRET` | yes | | The application's secret. Server-side only. |
| `PORT` | no | `9003` | Port to listen on. |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a
cd examples/typescript/express
npm start
```

```
notes API listening on :9003 (Keyora at http://localhost:8080)
```

| Command | What it does |
|---|---|
| `npm start` | Runs `src/server.ts` directly with `tsx`. |
| `npm run dev` | The same, restarting when a source file changes. |
| `npm run typecheck` | Type-checks without writing files. |
| `npm run build` | Compiles to `dist/`. |
| `npm run start:dist` | Runs the compiled `dist/server.js` with plain `node`. |

To check the running example against the shared contract (35 checks, about 70 seconds
because it waits for a token to expire; add `--skip-expiry` to skip that wait):

```sh
python3 examples/verify.py http://localhost:9003
```

## Example API requests

The responses shown are real output, with tokens shortened. Access tokens created by
`setup.sh` live for 60 seconds, so do not pause for long between the steps, or run the
refresh step again to get a new one.

### Public endpoint

```sh
curl -s http://localhost:9003/public
```

```json
{"message":"anyone can read this"}
```

### Register

```sh
curl -s -X POST http://localhost:9003/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'
```

`201 Created`:

```json
{"id":"e5429897-87ec-4483-9c10-f542b33075d4","tenant_id":"9276cb35-e993-4b32-a25c-a52306b98780","email":"ada@example.com","name":"Ada Lovelace","status":"active","email_verified":false,"created_at":"2026-11-23T15:10:30.079Z","updated_at":"2026-11-23T15:10:30.079Z"}
```

Registering the same address again gives `409` with Keyora's own error, passed through:

```json
{"error":{"code":"email_taken","message":"an account with this email already exists"}}
```

### Log in

```sh
curl -s -X POST http://localhost:9003/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

`200 OK`:

```json
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6Ik...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_YkV21W2o...","refresh_expires_in":2591999,"session_id":"f964c699-d8ca-4b11-b1d4-9c6d2ffec919","user":{"id":"e5429897-87ec-4483-9c10-f542b33075d4","email":"ada@example.com","name":"Ada Lovelace","status":"active","...":"..."}}
```

Keep the two tokens in shell variables for the next requests:

```sh
ACCESS='eyJhbGciOi...'     # access_token from the response
REFRESH='kyr_...'          # refresh_token from the response
```

A wrong password gives `401`:

```json
{"error":{"code":"invalid_credentials","message":"invalid email or password"}}
```

### Who am I (verified locally)

```sh
curl -s http://localhost:9003/me -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"e5429897-87ec-4483-9c10-f542b33075d4","email":"ada@example.com","roles":[],"permissions":[]}
```

Without a token, with a token that does not verify, and with an expired token (all `401`):

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is invalid"}}
{"error":{"code":"token_expired","message":"the access token has expired"}}
```

### Notes without a role

```sh
curl -s http://localhost:9003/notes -H "Authorization: Bearer $ACCESS"
```

`403 Forbidden`, because a new user has no roles:

```json
{"error":{"code":"forbidden","message":"you do not have permission to perform this action"}}
```

### Grant a role, then refresh

Roles are managed in Keyora, with the admin API. This call uses the admin key and IDs
from `examples/.env`; the user ID is the `id` returned by `/register` (also the `sub` in
`/me`). It answers `204 No Content`.

```sh
USER_ID='e5429897-87ec-4483-9c10-f542b33075d4'
curl -s -X PUT \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_EDITOR_ROLE_ID" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
```

The access token you already hold does not change. Roles are copied into a token when it
is issued, so refresh to get one that contains the new role:

```sh
curl -s -X POST http://localhost:9003/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

```json
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6Ik...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_-sheZRhk...","refresh_expires_in":2591999,"session_id":"f964c699-d8ca-4b11-b1d4-9c6d2ffec919"}
```

Store **both** new tokens in `ACCESS` and `REFRESH`. A refresh token works once: sending
the old one again answers `401 refresh_token_reused` and revokes the whole session.

### Notes and reports with the role

```sh
curl -s http://localhost:9003/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"text":"Welcome to Keyora","author":"system"}]}
```

```sh
curl -s -X POST http://localhost:9003/notes \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"text":"hello"}'
```

`201 Created`:

```json
{"text":"hello","author":"ada@example.com"}
```

```sh
curl -s http://localhost:9003/reports -H "Authorization: Bearer $ACCESS"
```

```json
{"total_notes":2}
```

### Who am I (asked from Keyora)

```sh
curl -s http://localhost:9003/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"e5429897-87ec-4483-9c10-f542b33075d4","email":"ada@example.com","roles":["editor"],"permissions":["notes:read","notes:write"]}
```

### Log out

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:9003/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

```
204
```

After logout, `/me/live` rejects the access token at once, while `/me` keeps accepting it
until it expires (at most 60 seconds here):

```sh
curl -s http://localhost:9003/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"error":{"code":"invalid_token","message":"the access token is no longer active"}}
```

The refresh token is gone too (`401`):

```json
{"error":{"code":"invalid_refresh_token","message":"refresh token is invalid or expired"}}
```

## How it works

### Calls that go to Keyora

| This application | Keyora |
|---|---|
| `POST /register` | `POST /api/v1/auth/register` |
| `POST /login` | `POST /api/v1/auth/login` |
| `POST /refresh` | `POST /api/v1/auth/refresh` |
| `POST /logout` | `POST /api/v1/auth/logout` |
| `GET /me/live` | `POST /api/v1/auth/introspect` |
| first protected request | `GET /.well-known/jwks.json` (then cached) |

Each API call carries the application's credentials as HTTP Basic authentication
(`client_id` as the username, `client_secret` as the password). Keyora answers with an
envelope, `{"data": ..., "meta": ...}` or `{"error": {"code", "message"}, "meta": ...}`.
This application unwraps it: on success the body is the `data` object, on failure it is
`{"error": ...}` with Keyora's status code and error code unchanged.

The client secret identifies your application to Keyora. It must stay on the server and
must never be shipped to a browser or a mobile app. That is the reason these four
endpoints exist: the browser talks to your server, and your server talks to Keyora. If
you have no server, register a `public` application in Keyora instead, which has no
secret.

### What is checked locally

`/me`, `/notes` and `/reports` make no request to Keyora. The `authenticate` middleware
in [`src/auth.ts`](src/auth.ts) calls `jwtVerify` from `jose`, which checks:

1. the algorithm is RS256 (`algorithms: ["RS256"]`, never the algorithm the token names);
2. the signature, against the key in Keyora's JWKS whose `kid` matches the token's;
3. `exp` is in the future;
4. `iss` equals `KEYORA_ISSUER`;
5. `aud` equals `KEYORA_CLIENT_ID`, so tokens issued to another application are refused.

The middleware then makes a sixth check itself: `token_use` equals `access`. An OIDC ID
token has the same issuer and audience as an access token, and must not be accepted as one.

The JWKS is fetched on the first protected request and cached in memory. If a token
names an unknown `kid`, `jose` fetches the key set again, so a key rotation in Keyora
needs no restart.

The verified claims are placed on `req.user`. Authorization is then a comparison against
them:

```ts
app.get("/me", authenticate, handler);                                    // any valid token
app.get("/notes", authenticate, requirePermission("notes:read"), handler); // every listed permission
app.get("/reports", authenticate, requireRole("editor"), handler);         // at least one listed role
```

### Local verification and introspection

Local verification cannot see a logout or a role change until the token expires or is
refreshed, because nothing asks Keyora. `/me/live` shows the alternative: it sends the
token to Keyora's introspection endpoint, which answers `{"active": false}` for a
revoked session and otherwise returns the user's current roles and permissions. That
costs one request to Keyora per call. Verify locally by default, keep access tokens
short-lived, and introspect only before operations that must not run on a revoked
session.

### Errors added by this application

| Status | Code | When |
|---|---|---|
| 401 | `missing_token` | No `Authorization: Bearer ...` header. |
| 401 | `invalid_token` | The token failed verification, or introspection reported it inactive. |
| 401 | `token_expired` | The signature is valid but `exp` has passed. Refresh and retry. |
| 403 | `forbidden` | The token is valid but lacks the required permission or role. |
| 400 | `invalid_json` | The request body is not a JSON object. |
| 400 | `validation_failed` | `POST /notes` without `text`. |
| 502 | `identity_unavailable` | Keyora could not be reached. |

## Troubleshooting

**Every protected request answers `401 invalid_token`, although login works.**
The issuer or the audience does not match. Decode the token's payload (the middle part,
base64url) and compare: `iss` must equal `KEYORA_ISSUER` exactly, including the scheme,
port and any trailing slash, and `aud` must equal `KEYORA_CLIENT_ID`. A typical cause is
running the example in a container with `KEYORA_URL=http://host.docker.internal:8080`
while Keyora issues tokens with `iss` `http://localhost:8080`: set `KEYORA_ISSUER` to the
latter. Another is using a token from a different application, or an `.env` left over
from an earlier `setup.sh` run.

**`502 identity_unavailable`.**
The example cannot reach Keyora at `KEYORA_URL`. Check `curl $KEYORA_URL/readyz`. Inside
a container, `localhost` is the container itself. Local verification keeps working
through an outage only once the keys have been cached by an earlier request.

**`KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required` at startup.**
`examples/.env` is missing or was not loaded into this shell. Run `examples/setup.sh`
(it needs `KEYORA_ADMIN_KEY`), then `set -a; . examples/.env; set +a` in the same shell
that runs `npm start`.

**`401 invalid_client` from `/register` or `/login`.**
The client ID or secret is not the one Keyora has. Re-run `examples/setup.sh` if Keyora's
database was recreated, and load the new `.env`.

**`401 token_expired` on a token that was just issued, or tokens that are rejected right
after login.**
The clocks of this machine and the Keyora host differ. Tokens carry `nbf` and `exp`, and
this example allows no tolerance. Synchronise the clocks (NTP). If a small drift cannot
be avoided, pass `clockTolerance: 5` (seconds) to `jwtVerify` in `src/auth.ts`. In
normal use `token_expired` simply means the 60-second token ran out: call `/refresh`.

**`403 forbidden` on `/notes` or `/reports`.**
The user has no role yet. Grant one with the admin API and then refresh, because roles
are copied into the access token when it is issued:

```sh
curl -X PUT \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_READER_ROLE_ID" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
```

`reader` carries `notes:read`; `editor` carries `notes:read` and `notes:write` and is
the role `/reports` requires. `USER_ID` is the `id` from `/register` or the `sub` from
`/me`.

**`401 refresh_token_reused`.**
A refresh token was sent twice. Keyora treats that as theft and revokes the session; log
in again. Always replace the stored refresh token with the one from the latest response.

**`429 rate_limited`.**
Keyora limits `/api/v1/auth/*` per client IP, and all requests forwarded by this example
come from one IP. Wait a moment and try again.

**`could not listen on port 9003`.**
Another process uses the port. Start with a different one: `PORT=9103 npm start`.
