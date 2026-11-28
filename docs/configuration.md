# Configuration

Keyora reads its configuration from environment variables at startup and validates all
of it at once: if anything is wrong it prints every problem and exits with status 2.
[`.env.example`](../.env.example) is a ready-to-copy template.

Durations use Go syntax: `30s`, `15m`, `720h`.

## Core

| Variable | Default | Description |
|---|---|---|
| `KEYORA_ADMIN_KEY` | *(unset)* | Root management credential, minimum 32 characters. Unset disables root access, so no tenants can be created through the API. |
| `KEYORA_ISSUER` | `http://localhost:8080` | Public base URL; the `iss` claim. Changing it invalidates issued tokens. |
| `KEYORA_HTTP_ADDR` | `:8080` | Listen address. |

## Database

| Variable | Default | Description |
|---|---|---|
| `KEYORA_DB_DRIVER` | `sqlite` | `sqlite`, `postgres` or `memory`. |
| `KEYORA_DB_DSN` | `file:./data/keyora.db` | Required for `postgres`, e.g. `postgres://user:pass@host:5432/keyora?sslmode=verify-full`. |
| `KEYORA_DB_MAX_OPEN_CONNS` | `20` | |
| `KEYORA_DB_MAX_IDLE_CONNS` | `5` | |
| `KEYORA_DB_CONN_MAX_LIFETIME` | `30m` | |
| `KEYORA_DB_PGBOUNCER` | `false` | Set `true` when the DSN points at PgBouncer or another pooler in transaction mode. Disables named prepared statements. |
| `KEYORA_AUTO_MIGRATE` | `true` | Apply pending migrations at startup. With `false`, run `keyora migrate` before starting a new version. |

For SQLite, Keyora adds the pragmas it relies on (foreign keys, WAL, a busy timeout)
unless the DSN already sets `_pragma`. `memory` keeps everything in process memory and
is for experiments and tests only.

## Signing keys

| Variable | Default | Description |
|---|---|---|
| `KEYORA_KEYS_DIR` | `./data/keys` | Directory of RSA private keys (`*.pem`). A first key is generated if it is empty. |
| `KEYORA_RSA_BITS` | `3072` | Size of generated keys. Minimum 2048. |

## Tokens and sessions

| Variable | Default | Description |
|---|---|---|
| `KEYORA_ACCESS_TOKEN_TTL` | `15m` | Default for new applications. 1 minute to 24 hours. |
| `KEYORA_REFRESH_TOKEN_TTL` | `720h` | Default for new applications. How long an unused session lives. |

Existing applications keep the lifetimes they were created with; change them per
application through the API.

## Passwords and abuse protection

| Variable | Default | Description |
|---|---|---|
| `KEYORA_PASSWORD_MIN_LENGTH` | `8` | Minimum 8. Maximum length is fixed at 256 bytes. |
| `KEYORA_PBKDF2_ITERATIONS` | `600000` | Minimum 100,000. Raising it upgrades hashes as users sign in. |
| `KEYORA_MAX_FAILED_LOGINS` | `5` | Consecutive failures before lockout. |
| `KEYORA_LOCKOUT_DURATION` | `15m` | |
| `KEYORA_RATE_LIMIT_PER_MINUTE` | `60` | Per client IP on auth endpoints. `0` disables. |
| `KEYORA_RATE_LIMIT_BURST` | `20` | |
| `KEYORA_TRUST_PROXY_HEADERS` | `false` | Take the client IP from the right-most `X-Forwarded-For` entry. Enable only behind your own proxy. |
| `KEYORA_CORS_ALLOWED_ORIGINS` | *(empty)* | Comma-separated extra origins. Application origins are allowed automatically. |

## Email

| Variable | Default | Description |
|---|---|---|
| `KEYORA_MAILER` | `log` | `log` writes messages, tokens included, to the log (development). `smtp` sends them. |
| `KEYORA_SMTP_HOST` | | Required for `smtp`. |
| `KEYORA_SMTP_PORT` | `587` | STARTTLS is used when the server offers it. |
| `KEYORA_SMTP_USERNAME` / `KEYORA_SMTP_PASSWORD` | | Optional PLAIN auth. |
| `KEYORA_SMTP_FROM` | | Required for `smtp`. |
| `KEYORA_REQUIRE_EMAIL_VERIFICATION` | `false` | Refuse sign-in until the address is verified. |
| `KEYORA_EMAIL_VERIFICATION_URL` | | Link template containing `{token}`. Empty: the email carries the bare token. |
| `KEYORA_PASSWORD_RESET_URL` | | Same, for password reset. |

## Tutorial compatibility

| Variable | Default | Description |
|---|---|---|
| `KEYORA_LEGACY_TUTORIAL_API` | `false` | Serve the original auth-tutorial endpoints. Migration only; see [legacy-tutorial-api.md](legacy-tutorial-api.md). |
| `KEYORA_LEGACY_TUTORIAL_CLIENT_ID` | | Required with the above: the confidential application legacy users belong to. |

## Transports

The REST API is always served on `KEYORA_HTTP_ADDR`. The official binary and image also
link the GraphQL and gRPC transports; all three expose the same operations with the
same authentication.

| Variable | Default | Description |
|---|---|---|
| `KEYORA_GRAPHQL_ENABLED` | `true` | Serve the [GraphQL API](graphql.md) at `POST /graphql` on the HTTP listener. |
| `KEYORA_GRAPHQL_INTROSPECTION` | `true` | Allow schema introspection queries. |
| `KEYORA_GRPC_ADDR` | *(empty)*; `:9090` in the container image | Listen address of the [gRPC API](grpc.md). Empty disables it. The listener is plaintext; terminate TLS at the proxy. |
| `KEYORA_GRPC_REFLECTION` | `true` | Serve gRPC server reflection. |

## Observability and timeouts

| Variable | Default | Description |
|---|---|---|
| `KEYORA_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `KEYORA_LOG_FORMAT` | `json` | `json` or `text`. Logs go to standard error. |
| `KEYORA_METRICS_ENABLED` | `true` | Serve `/metrics`. |
| `KEYORA_HTTP_READ_TIMEOUT` | `15s` | |
| `KEYORA_HTTP_WRITE_TIMEOUT` | `30s` | |
| `KEYORA_HTTP_IDLE_TIMEOUT` | `120s` | |
| `KEYORA_SHUTDOWN_TIMEOUT` | `20s` | Time allowed for in-flight requests on `SIGTERM`. |

## Commands

```
keyora [serve]        run the server (default)
keyora migrate        apply pending migrations and exit
keyora keygen         add a signing key to KEYORA_KEYS_DIR and exit
keyora healthcheck    exit 0 if a local server's /readyz answers 200 (used by the container)
keyora version
```
