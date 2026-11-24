# Go (Gin) example

The same notes API as the [standard-library example](../standard-library), built with
[Gin](https://github.com/gin-gonic/gin) and Keyora's Gin adapter. It follows the
contract in [examples/README.md](../../README.md).

## Prerequisites

- Go 1.26 or newer (required by current Gin releases)
- A running Keyora, prepared with `examples/setup.sh` (see [examples/README.md](../../README.md#run-an-example))

## Installation

```sh
cd examples/golang/gin
go mod download
```

Inside this repository `go.mod` uses `replace` directives to build against the local
source. In your own project, remove them and run:

```sh
go get github.com/rabbicse/keyora@latest github.com/rabbicse/keyora/adapters/gin@latest
```

The adapter is a separate Go module so that Gin is never a dependency of Keyora's core.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where this app reaches Keyora |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | `iss` required in tokens |
| `KEYORA_CLIENT_ID` | *(required)* | Application client ID; also the required `aud` |
| `KEYORA_CLIENT_SECRET` | *(required)* | Application secret. Server-side only |
| `PORT` | `9002` | Listen port |
| `GIN_MODE` | `release` | Set to `debug` for Gin's request log |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a
(cd examples/golang/gin && go run .)
# notes API (Gin) listening on :9002 (Keyora at http://localhost:8080)

python3 examples/verify.py http://localhost:9002
# 35 passed, 0 failed
```

## Example API requests

Identical to the [standard-library example](../standard-library/README.md#example-api-requests),
on port 9002:

```sh
curl -X POST localhost:9002/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse battery"}'
# 200 {"access_token":"eyJhbGci…","token_type":"Bearer","expires_in":60,"refresh_token":"kyr_…",…}

curl localhost:9002/me -H "Authorization: Bearer $TOKEN"
# 200 {"email":"ada@example.com","permissions":null,"roles":null,"sub":"8fa1…"}

curl localhost:9002/me -H "Authorization: Bearer not-a-token"
# 401 {"error":{"code":"invalid_token","message":"the access token is invalid or expired"}}
```

## How it works

```go
g, _ := guard.New(guard.Config{Issuer: issuer, Audience: clientID})

api := r.Group("/", keyoragin.Authenticate(g))            // 401 without a valid token
api.GET("/notes", keyoragin.RequirePermission("notes:read"), listNotes)   // 403 without it
api.GET("/reports", keyoragin.RequireRole("editor"), reports)

claims, _ := keyoragin.Claims(c)                           // inside a handler
```

`keyoragin.Authenticate` verifies the token locally through `guard` (signature, expiry,
issuer, audience) and stores the claims on the Gin context. The authorization
middleware fails closed: used without `Authenticate`, it answers 401.

Sign-in endpoints forward to Keyora with the client secret, which never leaves this
server. `/me/live` uses introspection.

## Troubleshooting

See the [standard-library example](../standard-library/README.md#troubleshooting); the
causes are the same.
