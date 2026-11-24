# Keyora example: Python + Flask

A small notes API that uses Keyora for sign-in and access control. It implements the
contract shared by all server examples (see [`examples/README.md`](../../README.md)).

| File | What it holds |
|---|---|
| `app.py` | The Flask app: routes and error handlers. |
| `auth.py` | Decorators: `@authenticated`, `@require_permission(...)`, `@require_role(...)`. |
| `keyora.py` | Configuration, the REST calls to Keyora (`requests`) and local JWT verification (`PyJWT`). |

## Prerequisites

- Python 3.9 or newer (tested with 3.11).
- A running Keyora, by default at `http://localhost:8080`.
- `examples/.env`, written by `examples/setup.sh`. It creates the tenant, the
  application, the `reader` and `editor` roles and the `notes:read` / `notes:write`
  permissions this example expects. See [`examples/README.md`](../../README.md).

## Installation

```sh
cd examples/python/flask
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Configuration

The example reads its settings from environment variables. It does not read `.env`
files itself; load `examples/.env` in your shell (see below).

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KEYORA_URL` | no | `http://localhost:8080` | Where this example reaches Keyora (API calls and JWKS). |
| `KEYORA_ISSUER` | no | value of `KEYORA_URL` | The `iss` value tokens must carry. Set it when Keyora's public issuer differs from the address this example uses to reach it, for example from inside a container. |
| `KEYORA_CLIENT_ID` | yes | – | The application's client ID. Also the `aud` value tokens must carry. |
| `KEYORA_CLIENT_SECRET` | yes | – | The application's secret. Server side only. |
| `PORT` | no | `9005` | Port to listen on (used by `python app.py`; `flask run` takes `--port`). |
| `HOST` | no | `127.0.0.1` | Address to bind to (used by `python app.py`; `flask run` takes `--host`). |

## How to run

From the repository root, load the settings, then start the server:

```sh
set -a; . examples/.env; set +a
cd examples/python/flask
.venv/bin/python app.py
```

or with the Flask command line, which takes the port as a flag (its default is 5000):

```sh
.venv/bin/flask run --port 9005
```

Both start Flask's development server. For anything beyond trying the example, run
the app under a WSGI server such as gunicorn or waitress.

Check it with the shared verification script, from the repository root:

```sh
python3 examples/verify.py http://localhost:9005
```

It should end with `35 passed, 0 failed`.

## Example API requests

The responses below are real output, shortened where marked with `...`.

Register a user and sign in:

```sh
curl -s -X POST http://localhost:9005/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'
```

```json
{"created_at":"2026-11-23T15:13:53.754Z","email":"ada@example.com","email_verified":false,"id":"90837e5c-b39b-4e36-9f51-372d45f8891c","name":"Ada Lovelace","status":"active","tenant_id":"9276cb35-...","updated_at":"2026-11-23T15:13:53.754Z"}
```

```sh
curl -s -X POST http://localhost:9005/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

```json
{"access_token":"eyJhbGciOiJSU...","expires_in":60,"refresh_expires_in":2591999,"refresh_token":"kyr_0ylxUNJx...","session_id":"d344f9b5-...","token_type":"Bearer","user":{"email":"ada@example.com","id":"90837e5c-...", ...}}
```

Keep the two tokens in shell variables for the next requests:

```sh
ACCESS='eyJhbGciOiJSU...'     # access_token from the login response
REFRESH='kyr_0ylxUNJx...'     # refresh_token from the login response
```

Call a protected endpoint. The token is verified inside this application:

```sh
curl -s http://localhost:9005/me -H "Authorization: Bearer $ACCESS"
```

```json
{"email":"ada@example.com","permissions":[],"roles":[],"sub":"90837e5c-b39b-4e36-9f51-372d45f8891c"}
```

Without a token, or with a broken one (both `401`):

```sh
curl -s http://localhost:9005/me
curl -s http://localhost:9005/me -H 'Authorization: Bearer nope'
```

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is invalid"}}
```

A new user has no roles, so the notes are off limits (`403`):

```sh
curl -s http://localhost:9005/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"error":{"code":"forbidden","message":"you do not have permission to perform this action"}}
```

Grant the `editor` role with Keyora's admin API (see [Troubleshooting](#troubleshooting)
for the command), then exchange the refresh token so the new access token carries the
role. Access tokens last 60 seconds in the example setup, so you will use this often:

```sh
curl -s -X POST http://localhost:9005/refresh -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

```json
{"access_token":"eyJhbGciOiJSU...","expires_in":60,"refresh_expires_in":2591999,"refresh_token":"kyr_...","session_id":"d344f9b5-...","token_type":"Bearer"}
```

A refresh token works once. Store the new `access_token` and `refresh_token` from
every refresh response; sending an old refresh token again revokes the session
(`401 refresh_token_reused`).

With the role in the token:

```sh
curl -s http://localhost:9005/notes -H "Authorization: Bearer $ACCESS"
curl -s -X POST http://localhost:9005/notes -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"text":"buy milk"}'
curl -s http://localhost:9005/reports -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"author":"system","text":"Welcome to Keyora"}]}
{"author":"ada@example.com","text":"buy milk"}
{"total_notes":2}
```

`/me/live` asks Keyora instead of trusting the token, so it shows roles as they are now:

```sh
curl -s http://localhost:9005/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"email":"ada@example.com","permissions":["notes:read","notes:write"],"roles":["editor"],"sub":"90837e5c-b39b-4e36-9f51-372d45f8891c"}
```

Sign out (`204`, empty body). After that `/me/live` refuses the access token at once,
while `/me` keeps accepting it until it expires:

```sh
curl -s -i -X POST http://localhost:9005/logout -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
curl -s http://localhost:9005/me/live -H "Authorization: Bearer $ACCESS"
```

```
HTTP/1.1 204 NO CONTENT

{"error":{"code":"invalid_token","message":"the access token is no longer active"}}
```

Errors from Keyora keep their status and code:

```sh
curl -s -X POST http://localhost:9005/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"wrong"}'
curl -s -X POST http://localhost:9005/register -H 'Content-Type: application/json' \
  -d '{"email":"zz@example.com","password":"x"}'
```

```json
{"error":{"code":"invalid_credentials","message":"invalid email or password"}}
{"error":{"code":"validation_failed","details":{"password":"must be at least 8 characters"},"message":"request validation failed"}}
```

## How it works

**Calls that go to Keyora.** `/register`, `/login`, `/refresh` and `/logout` are
forwarded to `POST /api/v1/auth/...` on Keyora with HTTP Basic authentication
(`client_id:client_secret`). Keyora answers with an envelope, `{"data": ..., "meta": ...}`
or `{"error": ..., "meta": ...}`; the example returns the `data` object on success and
`{"error": ...}` with Keyora's status on failure. `/me/live` calls
`POST /api/v1/auth/introspect` and answers `401 invalid_token` when Keyora reports
`"active": false`.

**Checks done locally.** `/me`, `/notes` and `/reports` never call Keyora per request.
`keyora.verify_token` fetches Keyora's public keys once from
`/.well-known/jwks.json` (cached by `jwt.PyJWKClient`) and then checks, for every
request: the algorithm is RS256, the signature is valid, `exp` is in the future, `iss`
equals `KEYORA_ISSUER`, `aud` equals `KEYORA_CLIENT_ID` and `token_use` equals `access`
(an OIDC ID token has the same issuer and audience, and is not an API credential). A token that fails only
the expiry check gets `401 token_expired`, which tells the client to refresh; anything
else gets `401 invalid_token`. The roles and permissions inside the verified token then
decide the `403`: `require_permission` needs every permission it lists, `require_role`
needs any one of the roles it lists.

**In Flask terms.** Authentication and authorization are decorators, and the verified
claims are on `flask.g.claims` for the duration of the request:

```python
@app.get("/me")
@authenticated
def me():
    return jsonify(g.claims)

@app.get("/notes")
@require_permission("notes:read")
def list_notes(): ...

@app.get("/reports")
@require_role("editor")
def reports(): ...
```

`require_permission` and `require_role` authenticate first, so they do not need
`@authenticated` as well. Put them below the route decorator. Flask's default error
pages are HTML; the error handlers in `app.py` replace them so every error is
`{"error": {"code", "message"}}`.

**The client secret stays on the server.** It lets its holder act as your application
towards Keyora. Never put it in browser JavaScript, a mobile app or a public repository.
The browser talks to this API; only this API talks to Keyora with the secret.

## Troubleshooting

When a token is rejected, the server log states the reason
(`access token rejected: ...`). The HTTP response deliberately does not.

| Symptom | Likely cause and fix |
|---|---|
| The server exits with `KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required` | `examples/.env` is missing or was not loaded into this shell. Run `examples/setup.sh` once, then `set -a; . examples/.env; set +a` in the shell that starts the server. |
| Every token gets `401 invalid_token`; the log says `Invalid issuer` | `KEYORA_ISSUER` does not equal the `iss` claim. It must be exactly the issuer Keyora is configured with (scheme, host, port, no trailing slash). This is common when the example reaches Keyora on an internal address: keep `KEYORA_URL` internal and set `KEYORA_ISSUER` to the public one. |
| `401 invalid_token`; the log says `Audience doesn't match` | The token was issued to a different application. `KEYORA_CLIENT_ID` must be the client ID of the application the user signed in through. |
| `401 invalid_token` on `/me` and `502 identity_unavailable` on `/login` or `/me/live` | Keyora is not reachable at `KEYORA_URL`. Check with `curl $KEYORA_URL/.well-known/jwks.json`. Without the keys no token can be verified, so local verification fails as well until they have been fetched once. |
| `401 token_expired` on a token you just received, or expired tokens accepted for a while | The clocks of this machine and the Keyora host disagree. Synchronise both (NTP). If a small skew cannot be avoided, pass `leeway=<seconds>` to `jwt.decode` in `keyora.py`. |
| `401 token_expired` after a minute | Expected: the example setup issues 60-second access tokens. Call `/refresh`. |
| `403 forbidden` on `/notes` or `/reports` | The user has no role yet. Grant one (below), then call `/refresh`: roles are copied into the access token when it is issued, so the old token still lacks them. |
| `401 invalid_client` from `/login` | `KEYORA_CLIENT_SECRET` is wrong, for example after rotating the secret or re-running `setup.sh` without reloading `.env`. |

### Granting a role

Roles are assigned in Keyora, with the admin key, not through this example. With
`examples/.env` loaded and the user's `id` from the `/register` response:

```sh
USER_ID=90837e5c-b39b-4e36-9f51-372d45f8891c
curl -s -i -X PUT \
  "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/$USER_ID/roles/$KEYORA_EDITOR_ROLE_ID" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"
```

```
HTTP/1.1 204 No Content
```

`KEYORA_READER_ROLE_ID` grants `notes:read` only; `KEYORA_EDITOR_ROLE_ID` grants the
`editor` role with `notes:read` and `notes:write`. Then call `/refresh` (or sign in
again) to get an access token that contains the new role.
