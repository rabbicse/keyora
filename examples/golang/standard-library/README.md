# Go (net/http) example

A notes API protected by Keyora, using only the Go standard library and Keyora's
dependency-free [`guard`](../../../guard) package. It follows the contract in
[examples/README.md](../../README.md).

## Prerequisites

- Go 1.24 or newer
- A running Keyora, prepared with `examples/setup.sh` (see [examples/README.md](../../README.md#run-an-example))

## Installation

Nothing to install: the example has no third-party dependencies.

```sh
cd examples/golang/standard-library
go build ./...
```

Inside this repository `go.mod` uses a `replace` directive to build against the local
source. In your own project, drop that line and run
`go get github.com/rabbicse/keyora@latest`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where this app reaches Keyora |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | `iss` required in tokens |
| `KEYORA_CLIENT_ID` | *(required)* | Application client ID; also the required `aud` |
| `KEYORA_CLIENT_SECRET` | *(required)* | Application secret. Server-side only |
| `PORT` | `9001` | Listen port |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a
(cd examples/golang/standard-library && go run .)
# notes API listening on :9001 (Keyora at http://localhost:8080)
```

Check it:

```sh
python3 examples/verify.py http://localhost:9001
# 35 passed, 0 failed
```

## Example API requests

```sh
curl -X POST localhost:9001/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}'
# 201 {"id":"8fa1…","email":"ada@example.com","name":"Ada","status":"active","email_verified":false,…}

curl -X POST localhost:9001/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'
# 200 {"access_token":"eyJhbGci…","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_…",…}

TOKEN=<access_token>

curl localhost:9001/me -H "Authorization: Bearer $TOKEN"
# 200 {"email":"ada@example.com","permissions":null,"roles":null,"sub":"8fa1…"}

curl localhost:9001/notes -H "Authorization: Bearer $TOKEN"
# 403 {"error":{"code":"forbidden","message":"you do not have permission to perform this action"}}

curl localhost:9001/me
# 401 {"error":{"code":"missing_token","message":"a bearer access token is required"}}
```

`/notes` answers 403 until the user has a role carrying `notes:read`. Grant one with
the admin API (IDs are in `examples/.env`), then refresh to get a token that carries it:

```sh
curl -X PUT "$KEYORA_URL/api/v1/tenants/$KEYORA_TENANT_ID/users/<user id>/roles/$KEYORA_READER_ROLE_ID" \
  -H "Authorization: Bearer $KEYORA_ADMIN_KEY"

curl -X POST localhost:9001/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"kyr_…"}'
```

## How it works

- [`keyora.go`](keyora.go) calls Keyora's REST API with the client credentials.
  `/register`, `/login`, `/refresh` and `/logout` forward to it and unwrap the envelope.
- [`main.go`](main.go) builds a `guard.Guard` with the issuer and audience, and wraps
  handlers:

  ```go
  mux.Handle("GET /notes", g.Middleware(guard.RequirePermission("notes:read")(handler)))
  mux.Handle("GET /reports", g.Middleware(guard.RequireRole("editor")(handler)))
  ```

  `guard` fetches Keyora's JWKS once, caches it, refetches on key rotation, and checks
  signature, expiry, issuer and audience locally — no call to Keyora per request.
- `/me/live` asks Keyora instead (introspection), so it sees a logout immediately.

The client secret never leaves this server.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required` | `examples/.env` is not loaded. Run `set -a; . examples/.env; set +a`. |
| Every request is `401 invalid_token` | `KEYORA_ISSUER` differs from Keyora's own `KEYORA_ISSUER`, or the token was issued to another application (wrong audience). |
| `401 invalid_client` from `/login` | Wrong client ID or secret; re-run `examples/setup.sh`. |
| `502 identity_unavailable` | Keyora is not reachable at `KEYORA_URL`. |
| `403 forbidden` on `/notes` | The user has no role with `notes:read`, or the token predates the grant — refresh. |
| Tokens rejected right after issue | Clock skew between machines; set `guard.Config.Leeway`. |
