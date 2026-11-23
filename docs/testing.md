# Testing

## Running the tests

```sh
make check          # what CI runs: format, vet, zero-dependency check, all tests with -race
make test           # all modules, no race detector
make cover          # coverage of the core module
make fuzz           # 30 seconds each on the token parser and the password verifier
make lint-openapi   # validate api/openapi.yaml (needs Node.js)
make vuln           # govulncheck on every module
```

The storage tests run against SQLite automatically. To include PostgreSQL:

```sh
docker run -d --name keyora-test-pg -p 55432:5432 \
  -e POSTGRES_USER=keyora -e POSTGRES_PASSWORD=keyora -e POSTGRES_DB=keyora postgres:17-alpine

cd cmd/keyora
KEYORA_TEST_POSTGRES_DSN='postgres://keyora:keyora@127.0.0.1:55432/keyora?sslmode=disable' go test ./...
```

Each PostgreSQL subtest creates and drops its own schema, so the database is left clean.

To run the suite through PgBouncer in transaction-pooling mode as well, start one in
front of that database and set `KEYORA_TEST_PGBOUNCER_DSN`:

```sh
docker network create keyora-test-net && docker network connect keyora-test-net keyora-test-pg
docker run -d --name keyora-test-pgb --network keyora-test-net -p 56432:5432 \
  -e DATABASE_URL='postgres://keyora:keyora@keyora-test-pg:5432/keyora' \
  -e POOL_MODE=transaction -e AUTH_TYPE=scram-sha-256 -e MAX_PREPARED_STATEMENTS=0 edoburu/pgbouncer

KEYORA_TEST_PGBOUNCER_DSN='postgres://keyora:keyora@127.0.0.1:56432/keyora?sslmode=disable' go test ./...
```

## What is tested, and where

| Layer | Location | What it proves |
|---|---|---|
| JWT | `jwt/` | Round trip; rejection of `alg: none`, HS256 key confusion, other algorithms, wrong key, unknown `kid`, tampered payload or signature, expiry, not-before, issuer, audience, malformed and oversized tokens; JWKS encoding; refusal of weak keys. Fuzzed. |
| Cryptography | `internal/security/` | Hashing, salts, work-factor upgrade, malformed hashes, key generation, rotation, file permissions, refusal to overwrite keys. Fuzzed. |
| Storage contract | `internal/store/storetest/` | One suite run against the memory store, SQLite, PostgreSQL, and PostgreSQL through PgBouncer in transaction mode: CRUD, constraints, pagination, filters, atomic counters, single-use tokens and codes under concurrency, cascades, expiry purge, tenant isolation, and injection payloads stored inertly. |
| Use cases | `internal/service/` | Registration, login, enumeration resistance, lockout and recovery, refresh rotation, reuse detection, concurrent refresh, logout, forged and stale tokens, introspection, RBAC, email verification, password reset and change, client authentication, tenant suspension and isolation. |
| HTTP API | `internal/httpapi/` | Full flows over real HTTP; the envelope and headers; malformed JSON, unknown fields, oversized and deeply nested bodies; injection payloads; privilege escalation against every management endpoint; cross-tenant access; CORS; rate limiting; proxy header trust; metrics. |
| OAuth 2.0 | `internal/httpapi/oauth_test.go` | Authorization code flow with PKCE through a cookie-keeping client: verifier enforcement, single use, replay revocation, expiry, client and tenant binding, redirect-URI validation, open-redirect refusal, parameter escaping, login CSRF, lockout on the hosted page. |
| OpenID Connect | `internal/httpapi/oidc_legacy_test.go` | ID token contents per scope, `nonce`, userinfo, discovery, and refusal of ID tokens as access tokens. |
| Tutorial compatibility | same file | The original endpoints end to end, plus the hardening around them: no enumeration, single-use challenges and login tokens, lockout, no cross-redemption of codes between flows, and that the mode is off by default. |
| API description | `internal/httpapi/openapi_test.go` | Every served route is in `api/openapi.yaml` and every documented route is served. |
| Go SDK | `guard/`, `adapters/gin/` | Middleware decisions, JWKS caching, key rotation, behaviour during a Keyora outage, protection against JWKS-fetch flooding. |
| Process | `cmd/keyora/` | The real binary wiring: configuration, migrations, serving, restart with data and keys intact, graceful shutdown, and the CLI commands. |
| Other languages | `examples/verify.py` | The same 34 black-box checks against each example application and a live Keyora. |

## Conventions

- **Time is injected.** Services take a clock, so expiry, lockout and token lifetime
  tests advance time instead of sleeping.
- **Security tests assert the refusal.** A test for "cannot do X" must fail if the
  check is removed. When adding a security rule, break it on purpose once and confirm
  a test notices.
- **New storage behaviour goes in `storetest`**, never in a backend-specific test, so
  every backend has to honour it.
- **HTTP tests use a real listener** (`httptest.NewServer`), so the middleware chain is
  exercised, not bypassed.
- **Fast hashing in tests.** Tests configure a low PBKDF2 iteration count; a separate
  test pins the production default.
- **The spec cannot drift.** Adding a route without documenting it fails the build.

## Verifying the examples

With Keyora running and `examples/setup.sh` done:

```sh
set -a; . examples/.env; set +a
(cd examples/golang/standard-library && go run .) &
python3 examples/verify.py http://localhost:9001
```

The script registers a user, signs in, checks rejection of tampered and
wrong-audience tokens, grants roles, refreshes, waits for a real token to expire,
logs out and replays a refresh token. See [examples/README.md](../examples/README.md).

## What is not tested

Stated plainly, so nobody assumes otherwise:

- **Load and performance.** There are no benchmarks or load tests.
- **SMTP delivery.** The mailer is exercised through a recorder, not a real server.
- **Multi-instance behaviour** is covered only through the database-level atomicity
  tests, not by running several processes.
- **The release workflow** and published container images.
- **Browsers.** The sign-in page is tested over HTTP with a cookie jar and was checked
  by hand in Chromium; there is no automated browser suite.
