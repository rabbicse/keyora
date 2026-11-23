# Architecture

## Design goals

1. **The core depends on nothing but the Go standard library.** Every third-party
   package is confined to a separate Go module that the core never imports.
2. **Identity logic does not know about HTTP or SQL.** It can be tested in memory and
   served by any transport.
3. **Tenant isolation is enforced at the lowest layer**, not by callers remembering to
   filter.
4. **Pragmatic over layered.** One package per concern, interfaces only where there are
   really two implementations.

## Repository layout

```
keyora/
├── go.mod                    core module — zero dependencies
├── jwt/                      public: RS256 JWT + JWKS (sign, verify)
├── guard/                    public: verify Keyora tokens in a Go service (net/http middleware)
├── api/openapi.yaml          REST API description (embedded into the binary)
├── internal/
│   ├── domain/               entities and the error vocabulary
│   ├── security/             password hashing, random tokens, signing key ring
│   ├── service/              use cases: auth, tokens, sessions, RBAC, tenants, applications
│   ├── store/                persistence port (one interface)
│   │   ├── memory/           in-memory adapter
│   │   ├── sqlstore/         PostgreSQL (direct or via PgBouncer) and SQLite adapter + migrations
│   │   └── storetest/        conformance suite every implementation must pass
│   ├── httpapi/              REST delivery: routing, middleware, envelope, metrics
│   ├── config/               environment configuration
│   ├── mailer/               SMTP and development mailers
│   ├── ratelimit/            token-bucket limiter
│   └── server/               wiring, CLI, graceful shutdown
├── cmd/keyora/               server binary — own module, links the database drivers
├── adapters/gin/             Gin middleware — own module
├── examples/                 integrations in Go, TypeScript, Python, Java, .NET, PHP
├── deploy/                   Compose, nginx and Caddy examples
└── docs/
```

### Why three modules

`database/sql` is in the standard library, but drivers are not, and a server that
cannot talk to a database is not useful. Rather than give up the zero-dependency core,
the drivers live in the module that builds the binary:

| Module | Imports | Why separate |
|---|---|---|
| `github.com/rabbicse/keyora` | standard library only | The library others import and audit. `make check-deps` fails the build if it ever gains a dependency. |
| `…/keyora/cmd/keyora` | `pgx` (PostgreSQL), `modernc.org/sqlite` (pure-Go SQLite) | `sqlstore` speaks `database/sql`; this module only registers drivers. |
| `…/keyora/adapters/gin` | Gin | Only for applications that already use Gin. |

The nested modules use `replace` directives to build against the repository they sit
in, so the server is built from a checkout (or installed from a release binary or
container image) rather than with `go install …@version`.

The two drivers were chosen for being the maintained, widely used options that need no
cgo, which is what lets the binary stay static. Their standard-library alternative
would be to implement the PostgreSQL wire protocol and a storage engine by hand, which
is far more risk than a pinned, widely reviewed driver.

## Request path

```mermaid
flowchart TD
    R[HTTP request] --> M[httpapi.ServeHTTP<br/>request ID · security headers · panic recovery<br/>CORS · rate limit · access log · metrics]
    M --> H[Handler<br/>decode JSON strictly · identify caller]
    H -->|application credentials| S
    H -->|bearer token → Principal| S[service<br/>validation · policy · audit]
    S --> ST[store.Store]
    S --> K[security.KeyRing<br/>sign / verify]
    S --> ML[mailer]
    ST --> DB[(SQLite / PostgreSQL / memory)]
    S -->|domain.Error| H
    H --> E[envelope: data or error, plus meta.request_id]
```

- `httpapi` contains no business rules. It turns HTTP into calls on `service` and
  `domain.Error` into status codes.
- `service` returns `*domain.Error` values with a stable `Code`. Anything else is
  logged and reported to the client as an opaque `internal_error`.
- The middleware chain is a single function (`ServeHTTP`) rather than a stack of
  wrappers, so the order — which is security-relevant — is visible in one place.

## Data model

```mermaid
erDiagram
    TENANT ||--o{ APPLICATION : owns
    TENANT ||--o{ USER : owns
    TENANT ||--o{ ROLE : owns
    TENANT ||--o{ PERMISSION : owns
    TENANT ||--o{ AUDIT_EVENT : records
    ROLE }o--o{ PERMISSION : "role_permissions"
    USER }o--o{ ROLE : "user_roles"
    USER ||--o{ SESSION : has
    APPLICATION ||--o{ SESSION : "signed in through"
    SESSION ||--o{ REFRESH_TOKEN : rotates
    USER ||--o{ VERIFICATION_TOKEN : "email verify / password reset"
    SESSION ||--o{ AUTHORIZATION_CODE : "PKCE-bound, single use"

    TENANT { text id PK  text slug UK  text status }
    APPLICATION { text id PK  text client_id UK  text client_secret_hash  text type  text allowed_origins }
    USER { text id PK  text email "unique per tenant"  text password_hash  int failed_logins  bigint locked_until }
    SESSION { text id PK  bigint expires_at  bigint revoked_at }
    REFRESH_TOKEN { text token_hash UK  bigint used_at }
```

Decisions worth knowing:

- **Users belong to a tenant, not to an application.** Every application in a tenant
  signs in the same users; a session records which application opened it. Coupling
  users to one application would make "one identity, every application" impossible.
- **A session is one sign-in on one device.** Refresh tokens rotate inside it. Revoking
  the session is what logout, password reset and reuse detection all do.
- **Access tokens are not stored.** They are self-contained and short-lived; what is
  stored is the session they point to (`sid`).
- **Permissions are a catalogue, roles reference them.** A role cannot be given a
  permission that does not exist in its tenant.
- **Timestamps are Unix milliseconds and lists are JSON text**, so one schema runs
  unchanged on SQLite and PostgreSQL.

## Multi-tenancy

A tenant is a hard boundary. Isolation is enforced in three places, and each is tested
on its own:

1. **Storage.** Every read and write of tenant-owned data takes the tenant ID, and the
   SQL carries `WHERE tenant_id = ?`. An ID from another tenant is simply not found.
   Cross-tenant references are refused — for example a role cannot be assigned to a
   user of another tenant, because the assignment checks that both rows belong to the
   tenant in one query.
2. **Tokens.** Access tokens carry `tid`. Introspection answers `active: false` to an
   application of a different tenant. A refresh token only works for the application
   that issued it.
3. **Management API.** The tenant is in the path (`/api/v1/tenants/{tenant_id}/…`) and
   one function, `tenantAdmin`, decides access to it: the caller holds the root key, or
   is a user of *that* tenant with the `keyora:admin` permission.

The same email address in two tenants is two unrelated accounts with separate
passwords.

What tenancy does **not** give you today: per-tenant signing keys or issuers, per-tenant
password policy, or per-tenant rate limits. All tenants share one key ring and one
issuer.

## Storage abstraction

There is a single `store.Store` interface, with these properties:

- **Atomic operations are methods, not transactions handed to callers.**
  `ConsumeRefreshToken` is one conditional `UPDATE`; `IncrementFailedLogins` is one
  `UPDATE … RETURNING`. Callers cannot get the locking wrong because they never see it.
- **No driver types leak.** `sqlstore` maps driver errors to `domain.ErrNotFound` /
  `ErrConflict` by SQLSTATE or message, without importing a driver.
- **One conformance suite** (`storetest`) runs against the memory store, SQLite,
  PostgreSQL, and PostgreSQL through PgBouncer in transaction-pooling mode. A new backend is done when the suite passes.

Adding MySQL means: a dialect switch for placeholders and upsert syntax in `sqlstore`,
a driver import in `cmd/keyora`, and a run of the suite.

## Extension points

The pieces that planned features plug into already exist:

| Planned | Hooks into |
|---|---|
| Single sign-on across applications | A browser session cookie checked in the authorization endpoint before showing the sign-in page |
| Social / external identity providers | A second credential type next to the password on `User` |
| MFA, passkeys | A step between password verification and `issueTokens` in `service.Login` |
| MySQL | `sqlstore` dialects |
| Webhooks, SIEM export | `service.audit`, the single place every security event passes through |
