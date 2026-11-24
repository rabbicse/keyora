# Keyora example: Ruby + Sinatra

A small notes API that uses Keyora for sign-in and access control. It implements the
contract shared by all server examples (see [`examples/README.md`](../../README.md)).

| File | What it holds |
|---|---|
| `app.rb` | The Sinatra app: routes and error handlers. |
| `auth.rb` | A Sinatra extension: the `claims` helper and the route conditions `authenticated:`, `permission:` and `role:`. |
| `keyora.rb` | Configuration, the REST calls to Keyora (`Net::HTTP`), the JWKS cache and local JWT verification (`jwt` gem). |
| `Gemfile`, `Gemfile.lock` | Dependencies: `sinatra`, `puma`, `rackup`, `jwt`. |
| `Dockerfile` | For running the example without a local Ruby. |

## Prerequisites

- Either Docker, or Ruby 3.3 or newer with Bundler (tested with Ruby 3.3 in the Docker
  image). Puma compiles a C extension on install, so a native install needs a C compiler.
- A running Keyora, by default at `http://localhost:8080`.
- `examples/.env`, written by `examples/setup.sh`. It creates the tenant, the
  application, the `reader` and `editor` roles and the `notes:read` / `notes:write`
  permissions this example expects. See [`examples/README.md`](../../README.md).

## Installation

With a local Ruby:

```sh
cd examples/ruby/sinatra
bundle config set --local path vendor/bundle
bundle install
```

With Docker, build the image from the repository root:

```sh
docker build -t keyora-example-ruby-sinatra examples/ruby/sinatra
```

## Configuration

The example reads its settings from environment variables. It does not read `.env`
files itself; load `examples/.env` in your shell, or pass it to Docker with `--env-file`
(see below).

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `KEYORA_URL` | no | `http://localhost:8080` | Where this example reaches Keyora (API calls and JWKS). |
| `KEYORA_ISSUER` | no | value of `KEYORA_URL` | The `iss` value tokens must carry. Set it when Keyora's public issuer differs from the address this example uses to reach it, for example from inside a container. |
| `KEYORA_CLIENT_ID` | yes | – | The application's client ID. Also the `aud` value tokens must carry. |
| `KEYORA_CLIENT_SECRET` | yes | – | The application's secret. Server side only. |
| `PORT` | no | `9012` | Port to listen on. |
| `HOST` | no | `127.0.0.1` (`0.0.0.0` in the Docker image) | Address to bind to. |

## How to run

### With a local Ruby

From the repository root, load the settings, then start the server:

```sh
set -a; . examples/.env; set +a
cd examples/ruby/sinatra
bundle exec ruby app.rb
```

This starts Puma through Sinatra in the `development` environment, in which Sinatra
only answers requests whose `Host` header is `localhost`, a `.localhost` or `.test`
name, or an IP address. Set `APP_ENV=production` to lift that, as the Docker image does.

### With Docker

Inside a container, `localhost` is the container itself, so Keyora on your machine is
reached at `host.docker.internal`. Tokens still say `iss = http://localhost:8080`, which
is why `KEYORA_ISSUER` is set separately. From the repository root:

```sh
docker run --rm --name keyora-example-ruby-sinatra -p 9012:9012 \
  --env-file examples/.env \
  -e KEYORA_URL=http://host.docker.internal:8080 \
  -e KEYORA_ISSUER=http://localhost:8080 \
  keyora-example-ruby-sinatra
```

On Linux, add `--add-host=host.docker.internal:host-gateway`.

The image runs as an unprivileged user and binds to `0.0.0.0:9012`.

### Check it

With the shared verification script, from the repository root:

```sh
python3 examples/verify.py http://localhost:9012
```

It should end with `35 passed, 0 failed`.

## Example API requests

The responses below are real output, shortened where marked with `...` (the note list
is shown as on a freshly started server).

Register a user and sign in:

```sh
curl -s -X POST http://localhost:9012/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'
```

```json
{"id":"249fd68b-6614-4f95-8626-f5c88c29670a","tenant_id":"2dd6b34e-bcf6-473d-896b-5acb74bd80ac","email":"ada@example.com","name":"Ada Lovelace","status":"active","email_verified":false,"created_at":"2026-11-24T07:50:41.61Z","updated_at":"2026-11-24T07:50:41.61Z"}
```

```sh
curl -s -X POST http://localhost:9012/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

```json
{"access_token":"eyJhbGciOiJSU...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_0vkA...","refresh_expires_in":2592000,"session_id":"34e39fe6-6900-47aa-a5e4-479ec97e5d06","user":{"id":"249fd68b-6614-4f95-8626-f5c88c29670a","email":"ada@example.com",...}}
```

Keep the two tokens in shell variables for the next requests:

```sh
ACCESS='eyJhbGciOiJSU...'     # access_token from the login response
REFRESH='kyr_...'             # refresh_token from the login response
```

Call a protected endpoint. The token is verified inside this application:

```sh
curl -s http://localhost:9012/me -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"249fd68b-6614-4f95-8626-f5c88c29670a","email":"ada@example.com","roles":[],"permissions":[]}
```

Without a token, or with a broken one (both `401`):

```sh
curl -s http://localhost:9012/me
curl -s http://localhost:9012/me -H 'Authorization: Bearer nope'
```

```json
{"error":{"code":"missing_token","message":"a bearer access token is required"}}
{"error":{"code":"invalid_token","message":"the access token is invalid"}}
```

A new user has no roles, so the notes are off limits (`403`):

```sh
curl -s http://localhost:9012/notes -H "Authorization: Bearer $ACCESS"
```

```json
{"error":{"code":"forbidden","message":"you do not have permission to perform this action"}}
```

Grant the `editor` role with Keyora's admin API (see [Troubleshooting](#troubleshooting)
for the command), then exchange the refresh token so the new access token carries the
role. Access tokens last 60 seconds in the example setup, so you will use this often:

```sh
curl -s -X POST http://localhost:9012/refresh -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

```json
{"access_token":"eyJhbGciOiJSU...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_w0Rt...","refresh_expires_in":2591999,"session_id":"34e39fe6-6900-47aa-a5e4-479ec97e5d06"}
```

A refresh token works once. Store the new `access_token` and `refresh_token` from
every refresh response; sending an old refresh token again revokes the session
(`401 refresh_token_reused`).

With the role in the token:

```sh
curl -s http://localhost:9012/notes -H "Authorization: Bearer $ACCESS"
curl -s -X POST http://localhost:9012/notes -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"text":"buy milk"}'
curl -s http://localhost:9012/reports -H "Authorization: Bearer $ACCESS"
```

```json
{"notes":[{"text":"Welcome to Keyora","author":"system"}]}
{"text":"buy milk","author":"ada@example.com"}
{"total_notes":2}
```

`/me/live` asks Keyora instead of trusting the token, so it shows roles as they are now:

```sh
curl -s http://localhost:9012/me/live -H "Authorization: Bearer $ACCESS"
```

```json
{"sub":"249fd68b-6614-4f95-8626-f5c88c29670a","email":"ada@example.com","roles":["editor"],"permissions":["notes:read","notes:write"]}
```

Sign out (`204`, empty body). After that `/me/live` refuses the access token at once,
while `/me` keeps accepting it until it expires:

```sh
curl -s -i -X POST http://localhost:9012/logout -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
curl -s http://localhost:9012/me/live -H "Authorization: Bearer $ACCESS"
```

```
HTTP/1.1 204 No Content

{"error":{"code":"invalid_token","message":"the access token is no longer active"}}
```

Errors from Keyora keep their status and code:

```sh
curl -s -X POST http://localhost:9012/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"wrong"}'
curl -s -X POST http://localhost:9012/register -H 'Content-Type: application/json' \
  -d '{"email":"zz@example.com","password":"x"}'
```

```json
{"error":{"code":"invalid_credentials","message":"invalid email or password"}}
{"error":{"code":"validation_failed","message":"request validation failed","details":{"password":"must be at least 8 characters"}}}
```

## How it works

**Calls that go to Keyora.** `/register`, `/login`, `/refresh` and `/logout` are
forwarded to `POST /api/v1/auth/...` on Keyora with HTTP Basic authentication
(`client_id:client_secret`), using `Net::HTTP` from the standard library. Keyora answers
with an envelope, `{"data": ..., "meta": ...}` or `{"error": ..., "meta": ...}`; the
example returns the `data` object on success and `{"error": ...}` with Keyora's status
on failure. `/me/live` calls `POST /api/v1/auth/introspect` and answers
`401 invalid_token` when Keyora reports `"active": false`.

**Checks done locally.** `/me`, `/notes` and `/reports` never call Keyora per request.
`Keyora.verify_token` hands the token to `JWT.decode`, which checks:

1. The algorithm is RS256. It is pinned with `algorithms: ["RS256"]`; the token does
   not get to choose.
2. The signature verifies against the JWKS key whose `kid` matches the token's header.
3. `exp` is in the future.
4. `iss` equals `KEYORA_ISSUER`.
5. `aud` equals `KEYORA_CLIENT_ID`. Without this check, a token issued to any other
   application on the same Keyora would be accepted.

One more check follows the library call: the `token_use` claim must be `"access"`.
Keyora also issues OpenID Connect ID tokens, signed with the same key and carrying the
same issuer and audience, with `token_use` set to `"id"`. They pass all five checks
above, yet they state who signed in and are not a permission to call an API, so they
are refused.

A token that fails only the expiry check gets `401 token_expired`, which tells the
client to refresh; anything else gets `401 invalid_token`. The roles and permissions
inside the verified token then decide the `403`: `permission:` needs every permission
it lists, `role:` needs any one of the roles it lists.

**Key cache.** `Keyora::Jwks` fetches `${KEYORA_URL}/.well-known/jwks.json` on first
use and keeps the keys in memory for five minutes. If a token names a `kid` that is
not in the cache, the keys are fetched again and the lookup is repeated once, so a key
rotation in Keyora needs no restart. Those extra fetches are at least ten seconds
apart, because the `kid` is chosen by whoever sends the token. If Keyora is down, the
cached keys keep being used.

**In Sinatra terms.** `auth.rb` is a Sinatra extension. It adds route conditions for
authentication and authorization, and the verified claims are available from the
`claims` helper for the duration of the request:

```ruby
register Auth

get "/me", authenticated: true do
  JSON.generate(claims)
end

get "/notes", permission: "notes:read" do ... end

get "/reports", role: "editor" do ... end
```

`permission:` and `role:` authenticate first, so they do not need `authenticated:` as
well. Sinatra's default error pages are HTML; the `error` handlers in `app.rb` replace
them so every error is `{"error": {"code", "message"}}`.

**The client secret stays on the server.** It lets its holder act as your application
towards Keyora. Never put it in browser JavaScript, a mobile app or a public repository.
The browser talks to this API; only this API talks to Keyora with the secret.

## Troubleshooting

When a token is rejected, the server log states the reason
(`access token rejected: ...`). The HTTP response deliberately does not.

| Symptom | Likely cause and fix |
|---|---|
| The server exits with `KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required` | `examples/.env` is missing or was not loaded. Run `examples/setup.sh` once, then `set -a; . examples/.env; set +a` in the shell that starts the server, or pass `--env-file examples/.env` to Docker. |
| Every token gets `401 invalid_token`; the log says `Invalid issuer` | `KEYORA_ISSUER` does not equal the `iss` claim. It must be exactly the issuer Keyora is configured with (scheme, host, port, no trailing slash). This is the usual result of running the example in a container: keep `KEYORA_URL` at the address the container can reach and set `KEYORA_ISSUER=http://localhost:8080`. |
| `401 invalid_token`; the log says `Invalid audience` | The token was issued to a different application. `KEYORA_CLIENT_ID` must be the client ID of the application the user signed in through. |
| `401 invalid_token`; the log says `token_use is not "access"` | An ID token was sent as a bearer token. Send the `access_token`. |
| `401 invalid_token` on `/me` and `502 identity_unavailable` on `/login` or `/me/live` | Keyora is not reachable at `KEYORA_URL`; the log says `could not fetch the JWKS`. Check with `curl $KEYORA_URL/.well-known/jwks.json`. From a container, `localhost` does not work; use `http://host.docker.internal:8080` (on Linux with `--add-host=host.docker.internal:host-gateway`). |
| `401 token_expired` on a token you just received, expired tokens accepted for a while, or `401 invalid_token` on a fresh token with `Signature nbf has not been reached` in the log | The clocks of this machine and the Keyora host disagree. Synchronise both (NTP). With Docker Desktop the virtual machine's clock can fall behind the host's, typically after the computer slept; restarting Docker Desktop resets it. If a small skew cannot be avoided, pass `leeway: <seconds>` to `JWT.decode` in `keyora.rb`; keep it small. |
| `401 token_expired` after a minute | Expected: the example setup issues 60-second access tokens. Call `/refresh`. |
| `403 forbidden` on `/notes` or `/reports` | The user has no role yet. Grant one (below), then call `/refresh`: roles are copied into the access token when it is issued, so the old token still lacks them. |
| `403` with the plain-text body `Host not permitted` | Sinatra's development-mode host check: the request's `Host` header is not a local name. Set `APP_ENV=production`. |
| `401 invalid_client` from `/login` | `KEYORA_CLIENT_SECRET` is wrong, for example after rotating the secret or re-running `setup.sh` without reloading `.env`. |

### Granting a role

Roles are assigned in Keyora, with the admin key, not through this example. With
`examples/.env` loaded and the user's `id` from the `/register` response:

```sh
USER_ID=<id from the register response>
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
