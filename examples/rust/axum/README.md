# Keyora example: Rust + axum

A small notes API that uses Keyora for sign-in and access control. It implements the
contract shared by all server examples (see [`examples/README.md`](../../README.md)).

| File | What it holds |
|---|---|
| `src/main.rs` | The axum app: routes, handlers, startup and graceful shutdown. |
| `src/auth.rs` | The `Claims` extractor (a handler that takes `Claims` requires a valid access token) and `require_permission` / `require_role`. |
| `src/keyora.rs` | Configuration, the REST calls to Keyora (`reqwest`), the JWKS cache and local JWT verification (`jsonwebtoken`). |
| `src/error.rs` | The `{"error": {"code", "message"}}` response type. |
| `Cargo.toml`, `Cargo.lock` | Dependencies: `axum`, `tokio`, `reqwest` (rustls), `jsonwebtoken`, `serde`. |
| `Dockerfile` | For running the example without a local Rust toolchain. |

## Prerequisites

- Either Docker, or a current stable Rust toolchain (the example was built and tested
  with the `rust:1-alpine` Docker image; it has not been built natively on macOS or
  Windows).
- A running Keyora, by default at `http://localhost:8080`.
- `examples/.env`, written by `examples/setup.sh`. It creates the tenant, the
  application, the `reader` and `editor` roles and the `notes:read` / `notes:write`
  permissions this example expects. See [`examples/README.md`](../../README.md).

## Installation

With a local Rust toolchain:

```sh
cd examples/rust/axum
cargo build --release --locked
```

With Docker, build the image from the repository root (the first build compiles every
dependency and takes a few minutes):

```sh
docker build -t keyora-example-rust-axum examples/rust/axum
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
| `PORT` | no | `9011` | Port to listen on. |
| `HOST` | no | `127.0.0.1` (`0.0.0.0` in the Docker image) | Address to bind to. |

## How to run

### With a local Rust toolchain

From the repository root, load the settings, then start the server:

```sh
set -a; . examples/.env; set +a
cd examples/rust/axum
cargo run --release --locked
```

### With Docker

Inside a container, `localhost` is the container itself, so Keyora on your machine is
reached at `host.docker.internal`. Tokens still say `iss = http://localhost:8080`, which
is why `KEYORA_ISSUER` is set separately. From the repository root:

```sh
docker run --rm --name keyora-example-rust-axum -p 9011:9011 \
  --env-file examples/.env \
  -e KEYORA_URL=http://host.docker.internal:8080 \
  -e KEYORA_ISSUER=http://localhost:8080 \
  keyora-example-rust-axum
```

On Linux, add `--add-host=host.docker.internal:host-gateway`.

The image contains only the statically linked binary, runs as an unprivileged user and
binds to `0.0.0.0:9011`.

### Check it

With the shared verification script, from the repository root:

```sh
python3 examples/verify.py http://localhost:9011
```

It should end with `35 passed, 0 failed`.

## Example API requests

```sh
curl -s -X POST http://localhost:9011/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","name":"Ada Lovelace"}'

curl -s -X POST http://localhost:9011/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
# {"access_token":"eyJhbGciOiJSU...","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_...",...}

ACCESS='eyJhbGciOiJSU...'     # access_token from the login response
REFRESH='kyr_...'             # refresh_token from the login response

curl -s http://localhost:9011/me -H "Authorization: Bearer $ACCESS"
# {"sub":"...","email":"ada@example.com","roles":[],"permissions":[]}

curl -s http://localhost:9011/me
# {"error":{"code":"missing_token","message":"a bearer access token is required"}}

curl -s http://localhost:9011/notes -H "Authorization: Bearer $ACCESS"
# 403 {"error":{"code":"forbidden",...}}  — a new user has no roles yet

curl -s -X POST http://localhost:9011/refresh -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

Access tokens last 60 seconds in the example setup, so `/refresh` is used often. A
refresh token works once: store the new pair from every refresh response.

## How it works

**Calls that go to Keyora.** `/register`, `/login`, `/refresh` and `/logout` are
forwarded to `POST /api/v1/auth/...` on Keyora with HTTP Basic authentication
(`client_id:client_secret`). Keyora answers with an envelope, `{"data": ..., "meta": ...}`
or `{"error": ..., "meta": ...}`; the example returns the `data` object on success and
`{"error": ...}` with Keyora's status on failure. `/me/live` calls
`POST /api/v1/auth/introspect` and answers `401 invalid_token` when Keyora reports
`"active": false`.

**Checks done locally.** `/me`, `/notes` and `/reports` never call Keyora per request.
`Keyora::verify_token` in `src/keyora.rs` checks:

1. The algorithm is RS256. It is fixed in `Validation::new(Algorithm::RS256)`; the
   token does not get to choose.
2. The signature verifies against the JWKS key whose `kid` matches the token's header.
3. `exp` is in the future (and `nbf`, when present, is not).
4. `iss` equals `KEYORA_ISSUER`.
5. `aud` equals `KEYORA_CLIENT_ID`. Without this check, a token issued to any other
   application on the same Keyora would be accepted.
6. `token_use` equals `"access"`. Keyora also issues OpenID Connect ID tokens, signed
   with the same key and carrying the same issuer and audience, with `token_use` set to
   `"id"`. They state who signed in and are not a permission to call an API, so they
   are refused.

The time checks allow two seconds of clock difference between this machine and Keyora
(`validation.leeway`); the library's default of 60 seconds would double the life of a
60-second token.

A token that fails only the expiry check gets `401 token_expired`, which tells the
client to refresh; anything else gets `401 invalid_token`. The roles and permissions
inside the verified token then decide the `403`.

**Key cache.** The keys from `${KEYORA_URL}/.well-known/jwks.json` are fetched on first
use and kept in memory. If a token names a `kid` that is not in the cache, the keys are
fetched again and the lookup is repeated once, so a key rotation in Keyora needs no
restart.

**In axum terms.** `Claims` implements `FromRequestParts`, so asking for it in a
handler's arguments is what makes the route protected:

```rust
async fn me(claims: Claims) -> Json<Claims> {
    Json(claims)
}

async fn list_notes(State(state): App, claims: Claims) -> Result<Json<Value>, ApiError> {
    require_permission(&claims, &["notes:read"])?;
    ...
}
```

**The client secret stays on the server.** It lets its holder act as your application
towards Keyora. Never put it in browser JavaScript, a mobile app or a public repository.

## Troubleshooting

When a token is rejected, the server log states the reason
(`access token rejected: ...`). The HTTP response deliberately does not.

| Symptom | Likely cause and fix |
|---|---|
| The server exits at startup naming `KEYORA_CLIENT_ID` or `KEYORA_CLIENT_SECRET` | `examples/.env` is missing or was not loaded. Run `examples/setup.sh` once, then load the file or pass `--env-file examples/.env` to Docker. |
| Every token gets `401 invalid_token`; the log says `InvalidIssuer` | `KEYORA_ISSUER` does not equal the `iss` claim. In a container, keep `KEYORA_URL` at the address the container can reach and set `KEYORA_ISSUER=http://localhost:8080`. |
| `401 invalid_token`; the log says `InvalidAudience` | The token was issued to a different application. |
| `401 invalid_token`; the log says `token_use is "id"` | An ID token was sent as a bearer token. Send the `access_token`. |
| `401 invalid_token` on a fresh token; the log says `ImmatureSignature` | This machine's clock is more than two seconds behind Keyora's. Synchronise the clocks. With Docker Desktop the virtual machine's clock can fall behind after the computer slept; restarting Docker Desktop resets it. |
| `502` from `/login` or `/me/live` | Keyora is not reachable at `KEYORA_URL`. From a container, use `http://host.docker.internal:8080`. |
| `403 forbidden` on `/notes` or `/reports` | The user has no role yet. Grant one with Keyora's admin API (see the [Ruby example](../../ruby/sinatra/README.md#granting-a-role) for the command), then call `/refresh`. |
