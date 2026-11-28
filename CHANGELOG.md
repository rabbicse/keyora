# Changelog

All notable changes to Keyora are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain
breaking changes; they are marked **Breaking**.

## [Unreleased]

## [0.2.0] - 2026-11-28

### Changed

- **Breaking: Keyora is API only.** The hosted sign-in page is gone: Keyora serves no
  HTML, sets no cookies and never redirects a browser. `GET /api/v1/oauth/authorize`
  is removed (it answers `405`). `POST /api/v1/oauth/authorize` now takes a JSON body —
  the authorization request with its PKCE challenge plus the user's email and
  password — and returns the authorization code as JSON (`code`, `state`,
  `redirect_uri`, `redirect_to`, `expires_in`, `iss`). Codes are redeemed at the token
  endpoint exactly as before. Applications collect credentials in their own interface.
  OAuth client libraries that start the flow with a browser redirect no longer work
  against Keyora; the token, discovery and JWKS endpoints are unchanged.
- The `golang/pkce` example is now a command-line public client that runs the flow
  through the API, instead of a web app with a sign-in page.

### Added

- **GraphQL API** at `POST /graphql` (module `transport/graphql`): the same accounts,
  tenants, applications, users, roles, sessions, audit and OAuth token operations as
  REST, with the same credentials and the same error codes in `extensions.code`.
  `KEYORA_GRAPHQL_ENABLED` (default `true`) and `KEYORA_GRAPHQL_INTROSPECTION`
  (default `true`). See [docs/graphql.md](docs/graphql.md).
- **gRPC API** (module `transport/grpc`): 48 RPCs in nine services generated from
  `keyora.proto`, plus the standard health service and optional reflection. Errors
  carry the REST error code as `ErrorInfo.reason`. Off unless `KEYORA_GRPC_ADDR` is set
  (`:9090` in the container image); `KEYORA_GRPC_REFLECTION` (default `true`). See
  [docs/grpc.md](docs/grpc.md).
- The container image, Compose files, nginx and Caddy examples expose and proxy gRPC on
  port 9090. CI tests both transport modules.
- `internal/access`: one place that decides who is calling (bearer token or admin key,
  application credentials, tenant boundary, credential rate limit), used by every
  transport.
- An end-to-end test that boots the server with all three transports and uses one
  token across REST, GraphQL and gRPC.

### Fixed

- With `KEYORA_TRUSTED_PROXIES`, a request carrying several `X-Forwarded-For` header
  lines had its client address taken from the first line; it is now taken from the
  last line, the one the trusted proxy appended.
- A change to an application's allowed origins took up to 30 seconds to reach CORS
  checks; it now applies to the next request on the instance that made the change
  (other instances still pick it up within 30 seconds).
- The token endpoint reports every unusable code or refresh token as `invalid_grant`,
  in REST, GraphQL and gRPC alike.

- The Spring Boot example said Keyora serves no OpenID Connect discovery document; it
  does. The example still configures the JWKS URL directly, now with the actual reason.

## [0.1.0] - 2026-11-24

First version of Keyora, developed from the
[auth-tutorial](https://github.com/rabbicse/go-projects/tree/main/projects/auth-tutorial)
code. See [docs/assessment.md](docs/assessment.md) for what was kept and replaced.

### Added

- **Identity:** registration, login, profile, password change, email verification,
  password reset, account disable, brute-force lockout and unlock.
- **Tokens and sessions:** RS256 access tokens, JWKS endpoint, rotating opaque refresh
  tokens stored as hashes, refresh-token reuse detection, per-device sessions with
  listing and revocation, logout, signing-key rotation, live token introspection.
- **OAuth 2.0:** authorization code flow with mandatory PKCE (S256 only) and a hosted
  sign-in page; refresh-token and client-credentials grants; authorization server
  metadata (RFC 8414); `iss` in authorization responses (RFC 9207).
- **OpenID Connect** on the authorization code flow: ID tokens with `nonce`, the
  `openid`, `email` and `profile` scopes, a userinfo endpoint and a discovery document.
  ID tokens are marked `token_use: id` and refused as access tokens.
- **Tutorial compatibility mode** (`KEYORA_LEGACY_TUTORIAL_API`, off by default): the
  original auth-tutorial endpoints and challenge-response login, for migration, with a
  step-by-step migration guide.
- **Authorization:** roles and permissions per tenant, carried in access tokens;
  tenant administrators via the `keyora:admin` permission.
- **Multi-tenancy:** tenants, multiple confidential and public applications per tenant
  with their own credentials, allowed origins, redirect URIs and token lifetimes.
- **REST API** under `/api/v1` with a consistent envelope, structured error codes,
  pagination, filtering and request IDs; an OpenAPI 3 description served by the server.
- **Storage adapters:** in-memory, SQLite, and PostgreSQL — directly or through
  PgBouncer in transaction-pooling mode (`KEYORA_DB_PGBOUNCER`) — sharing one
  conformance suite, with embedded forward-only migrations.
- **Security:** PBKDF2-HMAC-SHA256 password hashing with transparent work-factor
  upgrade, per-IP rate limiting, CORS, security headers, strict request validation,
  audit trail.
- **Operations:** structured logging, liveness and readiness probes, Prometheus
  metrics, graceful shutdown, `serve` / `migrate` / `keygen` / `healthcheck` commands,
  a distroless non-root container image, Compose files, nginx and Caddy examples.
- **Go SDK:** the dependency-free `jwt` and `guard` packages, and a Gin adapter in its
  own module.
- **Examples** for Go (net/http, Gin, PKCE browser sign-in), TypeScript (Express, plain
  script), Python (FastAPI, Flask), Java (Spring Boot, plain Java), .NET (ASP.NET
  Core), PHP (plain PHP, Laravel), Rust (axum) and Ruby (Sinatra), with a shared
  verification script. Every example refuses ID tokens as API credentials.
- **Container image** published to `ghcr.io/rabbicse/keyora` for linux/amd64 and
  linux/arm64 on each release tag (and to Docker Hub when credentials are configured).

### Changed (relative to the tutorial)

- **Breaking:** the default login is password verification over TLS with server-side
  hashing. The tutorial's challenge–response login, whose stored verifier is
  password-equivalent, is available only in the opt-in compatibility mode.
- **Breaking:** Keyora's own endpoint paths and payloads are new, versioned and
  enveloped. The tutorial's paths are served in compatibility mode.
- **Breaking:** the authorization code flow now requires PKCE and a registered,
  exactly matching redirect URI.
- The server no longer depends on Gin or any JWT library; the core module has no
  third-party dependencies.

[Unreleased]: https://github.com/rabbicse/keyora/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rabbicse/keyora/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rabbicse/keyora/releases/tag/v0.1.0
