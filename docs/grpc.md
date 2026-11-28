# gRPC API

Keyora serves the operations of the versioned REST API (`/api/v1`) over gRPC too. Both
run on the same service, identify callers the same way and report the same error
codes; pick whichever fits your client.

The API is defined in the proto files under
[`transport/grpc/proto/keyora/v1`](../transport/grpc/proto/keyora/v1), package
`keyora.v1`. Every service, RPC and non-obvious field is described there; those files
are the reference. This page covers what is common to all RPCs.

Not available over gRPC: the readiness and metrics endpoints, the `/.well-known`
documents (JWKS, OAuth and OpenID Connect metadata), the OpenAPI description and the
tutorial-compatibility API. Fetch those over plain HTTP.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `KEYORA_GRPC_ADDR` | *(empty)* | Listen address, for example `:9090` or `127.0.0.1:9090`. Empty switches the gRPC API off. |
| `KEYORA_GRPC_REFLECTION` | `true` | Serve gRPC server reflection, so that generic tools can list the services and call them without the proto files. |

The gRPC API has a listener of its own, separate from the HTTP one. When it starts,
Keyora logs the address:

```json
{"time":"2026-11-28T08:12:14.063376+06:00","level":"INFO","msg":"grpc is listening","addr":"127.0.0.1:19090","reflection":true}
```

These settings of the HTTP API apply to gRPC as well:

- `KEYORA_ADMIN_KEY`: the root credential.
- `KEYORA_RATE_LIMIT_PER_MINUTE` and `KEYORA_RATE_LIMIT_BURST`: the limit on RPCs that
  take credentials. REST, GraphQL and gRPC calls from one address share one budget.
- `KEYORA_TRUST_PROXY_HEADERS`: take the client address from `x-forwarded-for` (see
  below).
- `KEYORA_SHUTDOWN_TIMEOUT`: on shutdown, no new RPCs are accepted and those in
  progress get this long to finish. Whatever is still open afterwards, including a
  health `Watch` stream a client has not closed, is cut off.

The gRPC transport is a separate Go module. The official binary links it; a custom
binary built from the core module alone does not, and logs a warning if
`KEYORA_GRPC_ADDR` is set.

### TLS and the reverse proxy

The listener is plaintext HTTP/2. This is the same deployment model as Keyora's HTTP
listener: bind it to localhost or a private network, and put a reverse proxy in front
that terminates TLS and forwards gRPC to it. There are no TLS settings in Keyora.
Passwords, client secrets and tokens travel in these RPCs, so do not expose the
plaintext listener to a network you do not control.

With `KEYORA_TRUST_PROXY_HEADERS=true`, Keyora takes the client address from the
right-most entry of the last `x-forwarded-for` metadata value, and falls back to the
address of the connection if that is not an IP address. The proxy must set or overwrite
that header with the address it saw. Without the setting the header is ignored. The
client address is used for rate limiting and recorded in sessions and audit events.

### Limits

- A request message may be at most 1 MiB. A larger one is refused with
  `RESOURCE_EXHAUSTED` before any RPC runs.
- Request metadata may be at most 64 KiB.
- All RPCs are unary. There is no streaming in the Keyora services.
- Clients may send HTTP/2 keepalive pings, also while no RPC is in progress, but not
  more often than every 30 seconds. A client that pings more often is disconnected.
- Keyora pings a connection that has been quiet for 2 minutes and closes it if there is
  no answer within 20 seconds. A connection that has carried no RPC for 15 minutes is
  closed; clients reconnect on their next call.

## Authentication

Credentials travel in request metadata, in the same form as the REST API's
`Authorization` header.

| Caller | Metadata | Used by |
|---|---|---|
| An application | `authorization: Basic base64(client_id:client_secret)`, or the `client_id` and `client_secret` fields of the request | `AuthService`, `OAuthService.Token` |
| A signed-in user | `authorization: Bearer <access token>` | `AccountService`, `OAuthService.UserInfo`, `AuthService.Logout` without a refresh token |
| The root administrator | `authorization: Bearer <KEYORA_ADMIN_KEY>` | `TenantService` and all management services |
| A tenant administrator | `authorization: Bearer <access token>` of a user who holds the `keyora:admin` permission | `TenantService.GetTenant` and the other management services, for the administrator's own tenant |

- When an application sends both the `Basic` metadata and the request fields, the
  metadata is used.
- A public application has no secret and sends its `client_id` alone.
- `AuthService.ConfirmEmail` and `AuthService.ResetPassword` take no application
  credentials: the emailed token is the credential.
- `OAuthService.Authorize` names the application in its `client_id` field and takes no
  client secret.
- An OpenID Connect ID token is not an access token and is refused
  (`UNAUTHENTICATED`, reason `invalid_token`).
- Every management RPC names the tenant in `tenant_id`. A tenant administrator who
  names another tenant gets `PERMISSION_DENIED`. An ID of another tenant's resource,
  sent together with the administrator's own `tenant_id`, gets `NOT_FOUND`.

Two more metadata keys are read:

| Key | Meaning |
|---|---|
| `origin` | The origin of the browser page the call is made for, when a gateway forwards browser calls. If present, it must be one of the application's `allowed_origins` for a public application's `AuthService` and `OAuthService.Token` calls and for every `OAuthService.Authorize` call; otherwise the call fails with `PERMISSION_DENIED`, reason `origin_not_allowed`. |
| `x-request-id` | See the next section. |

## Request IDs

Every RPC has a request ID. Send your own in the `x-request-id` metadata key (1 to 64
characters from `A-Z a-z 0-9 . _ -`); anything else is replaced by an ID Keyora
generates. The ID is returned in the response header metadata under the same key, is
part of every error (below), and appears in Keyora's log and in the audit events the
RPC causes.

Keyora logs one line per RPC, with the method, status code, duration, request ID and
client address. Messages and metadata are never logged.

```json
{"time":"2026-11-28T08:12:15.367696+06:00","level":"INFO","msg":"grpc request","request_id":"93d32b7d-4892-412f-8941-d302b923f2c9","method":"/keyora.v1.AuthService/Login","code":"Unauthenticated","duration_ms":144,"ip":"127.0.0.1"}
```

## Errors

A failed RPC returns a gRPC status. Its code tells the kind of failure:

| gRPC code | REST status | Meaning |
|---|---|---|
| `INVALID_ARGUMENT` | 400 | The request is invalid. |
| `UNAUTHENTICATED` | 401 | Credentials are missing or wrong. |
| `PERMISSION_DENIED` | 403 | The caller is known but may not do this. |
| `NOT_FOUND` | 404 | No such resource in this tenant. |
| `ALREADY_EXISTS` | 409 | A resource with this name, slug or email exists. |
| `FAILED_PRECONDITION` | 423 | The account is locked. |
| `RESOURCE_EXHAUSTED` | 429 | Rate limited. |
| `INTERNAL` | 500 | An error inside Keyora. The message is always `an internal error occurred`; the cause is in Keyora's log under the request ID. |

The status also carries one detail of type `google.rpc.ErrorInfo`:

| ErrorInfo field | Content |
|---|---|
| `reason` | The stable error code, for example `invalid_credentials`. These are the codes of the REST API (`error.code`); they are listed in [API conventions](api.md). |
| `domain` | Always `keyora`. |
| `metadata` | `request_id`, plus the details of the error. A `validation_failed` error has one entry per rejected field, such as `password: must be at least 8 characters`. `account_locked` and `rate_limited` have `retry_after_seconds`. |

Branch on `reason`, not on the status message: messages may be reworded, reasons are
part of the API.

Errors produced by gRPC itself, before an RPC of Keyora runs, have no `ErrorInfo`:
a message over the size limit (`RESOURCE_EXHAUSTED`), an unknown method
(`UNIMPLEMENTED`), a call that ran past its deadline (`DEADLINE_EXCEEDED`).

`OAuthService.Token` is deliberately coarse, like the REST token endpoint. It reports
`UNAUTHENTICATED` with reason `invalid_client` when the application cannot be
authenticated, `INVALID_ARGUMENT` with reason `unsupported_grant_type` for a grant it
does not serve, and `INVALID_ARGUMENT` with reason `invalid_grant` whenever the
authorization code or refresh token cannot be used. It gives no hint about the cause:
an unknown, expired or replayed code, a wrong verifier or redirect URI and a reused
refresh token all get the same answer. `AuthService.Refresh`, like
`POST /api/v1/auth/refresh`, does name the reason (`invalid_refresh_token`,
`refresh_token_reused`).

### Rate limiting

Every RPC of `AuthService` and `OAuthService` counts against the per-address limit on
requests that take credentials, like the REST routes under `/api/v1/auth` and
`/api/v1/oauth`. Over the limit, an RPC fails with `RESOURCE_EXHAUSTED`, reason
`rate_limited`, and `retry_after_seconds` in the error metadata. The other services
are not limited by Keyora.

## Services

Each RPC does what the REST route next to it does.

### AuthService

Registration, sign-in and tokens. Caller: an application.

| RPC | REST |
|---|---|
| `Register` | `POST /api/v1/auth/register` |
| `Login` | `POST /api/v1/auth/login` |
| `Refresh` | `POST /api/v1/auth/refresh` |
| `Logout` | `POST /api/v1/auth/logout` |
| `Introspect` | `POST /api/v1/auth/introspect` |
| `RequestEmailVerification` | `POST /api/v1/auth/email-verification/request` |
| `ConfirmEmail` | `POST /api/v1/auth/email-verification/confirm` |
| `ForgotPassword` | `POST /api/v1/auth/password/forgot` |
| `ResetPassword` | `POST /api/v1/auth/password/reset` |

`Logout` works in two ways: with a refresh token and application credentials, or with
an empty `refresh_token` and the user's access token as bearer credential.

### OAuthService

The OAuth 2.0 authorization code flow with PKCE, the token endpoint and OpenID Connect
userinfo.

| RPC | REST |
|---|---|
| `Authorize` | `POST /api/v1/oauth/authorize` |
| `Token` | `POST /api/v1/oauth/token` |
| `UserInfo` | `GET /api/v1/oauth/userinfo` |

`Authorize` takes the authorization request (`client_id`, `redirect_uri`,
`code_challenge` with method `S256`, and optionally `state`, `scope` and `nonce`)
together with the user's email and password, and returns the authorization code.
`Token` redeems it with `grant_type` `authorization_code` and the `code_verifier`; it
also serves the `refresh_token` and `client_credentials` grants.

### AccountService

A user's own account. Caller: the user.

| RPC | REST |
|---|---|
| `GetMe` | `GET /api/v1/users/me` |
| `UpdateMe` | `PATCH /api/v1/users/me` |
| `ChangePassword` | `POST /api/v1/users/me/password` |
| `ListMySessions` | `GET /api/v1/users/me/sessions` |
| `RevokeMySession` | `DELETE /api/v1/users/me/sessions/{session_id}` |

### TenantService

Caller: the root administrator; `GetTenant` also a tenant administrator.

| RPC | REST |
|---|---|
| `CreateTenant` | `POST /api/v1/tenants` |
| `ListTenants` | `GET /api/v1/tenants` |
| `GetTenant` | `GET /api/v1/tenants/{tenant_id}` |
| `UpdateTenant` | `PATCH /api/v1/tenants/{tenant_id}` |

### ApplicationService

Caller: the root administrator or a tenant administrator. The REST paths below, and
those of the following services, start with `/api/v1/tenants/{tenant_id}`.

| RPC | REST |
|---|---|
| `CreateApplication` | `POST …/applications` |
| `ListApplications` | `GET …/applications` |
| `GetApplication` | `GET …/applications/{id}` |
| `UpdateApplication` | `PATCH …/applications/{id}` |
| `DeleteApplication` | `DELETE …/applications/{id}` |
| `RotateApplicationSecret` | `POST …/applications/{id}/rotate-secret` |

The client secret is returned only by `CreateApplication` and
`RotateApplicationSecret`. No other RPC can read it; Keyora stores a hash.

### UserService

| RPC | REST |
|---|---|
| `CreateUser` | `POST …/users` |
| `ListUsers` | `GET …/users` |
| `GetUser` | `GET …/users/{id}` |
| `UpdateUser` | `PATCH …/users/{id}` |
| `DeleteUser` | `DELETE …/users/{id}` |
| `UnlockUser` | `POST …/users/{id}/unlock` |
| `ListUserRoles` | `GET …/users/{id}/roles` |
| `AssignUserRole` | `PUT …/users/{id}/roles/{role_id}` |
| `UnassignUserRole` | `DELETE …/users/{id}/roles/{role_id}` |

### RoleService

| RPC | REST |
|---|---|
| `CreatePermission` | `POST …/permissions` |
| `ListPermissions` | `GET …/permissions` |
| `DeletePermission` | `DELETE …/permissions/{id}` |
| `CreateRole` | `POST …/roles` |
| `ListRoles` | `GET …/roles` |
| `GetRole` | `GET …/roles/{id}` |
| `UpdateRole` | `PATCH …/roles/{id}` |
| `DeleteRole` | `DELETE …/roles/{id}` |
| `SetRolePermissions` | `PUT …/roles/{id}/permissions` |

### SessionService

| RPC | REST |
|---|---|
| `ListSessions` | `GET …/sessions` |
| `RevokeSession` | `DELETE …/sessions/{id}` |

### AuditService

| RPC | REST |
|---|---|
| `ListAuditEvents` | `GET …/audit-events` |

## Message conventions

- **Lists** take `limit` (1 to 100; 0 or unset means 20) and `offset`, and return the
  page together with `total`, the number of matching items across all pages. The
  filters are those of the REST API: `email` and `status` for users, `user_id` and
  `active_only` for sessions, `type` and `actor_id` for audit events.
- **Partial updates** (`UpdateTenant`, `UpdateApplication`, `UpdateUser`, `UpdateRole`)
  change only the fields that are set in the request. Scalar fields are declared
  `optional`, so that setting a field to `""` or `false` is different from leaving it
  out. `UpdateMe` has one such field, `name`, and it is required. The list fields of `UpdateApplication` (`redirect_uris`,
  `allowed_origins`) are wrapped in a `StringList` message: leave the field unset to
  keep the stored list, set it to replace the list, set it with no values to clear it.
- **Timestamps** are `google.protobuf.Timestamp`. A timestamp that does not apply, such
  as `revoked_at` of a session that is not revoked, is unset.
- **Lifetimes** (`expires_in`, `access_token_ttl_seconds` and the like) are whole
  seconds.
- **Status and type values** are the strings of the REST API: `active`, `disabled`,
  `suspended`, `confidential`, `public`.
- **IDs** are UUIDs, except `client_id` (`app_…`).

## A Go client

Go clients import the generated package
`github.com/rabbicse/keyora/transport/grpc/keyorapb`. It depends on gRPC and protobuf
only.

The program below signs a user in, calls an RPC with the access token, and shows how
to read an error. It expects an application and a user to exist; the
[integration guide](integration.md) explains how to create them.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

func main() {
	// Plaintext, for a Keyora on this machine. Through a TLS-terminating
	// proxy, use credentials.NewTLS instead.
	conn, err := grpc.NewClient(os.Getenv("KEYORA_GRPC_TARGET"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Sign in. The application identifies itself with its credentials.
	auth := keyorapb.NewAuthServiceClient(conn)
	login, err := auth.Login(ctx, &keyorapb.LoginRequest{
		ClientId:     os.Getenv("KEYORA_CLIENT_ID"),
		ClientSecret: os.Getenv("KEYORA_CLIENT_SECRET"),
		Email:        "ada@example.com",
		Password:     "correct horse battery",
	})
	if err != nil {
		log.Fatal(describe(err))
	}
	tokens := login.GetTokens()
	fmt.Printf("signed in as %s, session %s\n", login.GetUser().GetEmail(), tokens.GetSessionId())
	fmt.Printf("%s token, valid for %d seconds: %.16s...\n", tokens.GetTokenType(), tokens.GetExpiresIn(), tokens.GetAccessToken())

	// 2. Call an RPC as the user: the access token goes in the metadata.
	asUser := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tokens.GetAccessToken())
	var header metadata.MD
	me, err := keyorapb.NewAccountServiceClient(conn).GetMe(asUser, &keyorapb.GetMeRequest{}, grpc.Header(&header))
	if err != nil {
		log.Fatal(describe(err))
	}
	fmt.Printf("profile: %s <%s>, status %s, roles %v\n",
		me.GetUser().GetName(), me.GetUser().GetEmail(), me.GetUser().GetStatus(), me.GetRoles())
	if id := header.Get("x-request-id"); len(id) > 0 {
		fmt.Printf("request id: %s\n", id[0])
	}

	// 3. A failure: branch on the reason, not on the message.
	_, err = auth.Login(ctx, &keyorapb.LoginRequest{
		ClientId:     os.Getenv("KEYORA_CLIENT_ID"),
		ClientSecret: os.Getenv("KEYORA_CLIENT_SECRET"),
		Email:        "ada@example.com",
		Password:     "not the password",
	})
	fmt.Println(describe(err))
}

// describe renders a Keyora error: the gRPC status plus the stable reason
// from its ErrorInfo detail.
func describe(err error) string {
	st := status.Convert(err)
	for _, detail := range st.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok {
			return fmt.Sprintf("%s: %s (reason=%s domain=%s request_id=%s)",
				st.Code(), st.Message(), info.GetReason(), info.GetDomain(), info.GetMetadata()["request_id"])
		}
	}
	return fmt.Sprintf("%s: %s", st.Code(), st.Message())
}
```

Run against a local Keyora with `KEYORA_GRPC_ADDR=127.0.0.1:19090`, and with
`KEYORA_GRPC_TARGET=127.0.0.1:19090` and the application's credentials in the
program's environment, it prints:

```
signed in as ada@example.com, session 5192f563-acb6-4b4b-8bb1-35b73901b21c
Bearer token, valid for 900 seconds: eyJhbGciOiJSUzI1...
profile: Ada Lovelace <ada@example.com>, status active, roles []
request id: 8e7d48c8-ab08-4bb2-ac71-135e404732f8
Unauthenticated: invalid email or password (reason=invalid_credentials domain=keyora request_id=93d32b7d-4892-412f-8941-d302b923f2c9)
```

The access token is the same signed JWT the REST API issues. Your own services verify
it as described in [Authentication](authentication.md), without calling Keyora.

## Health checking and reflection

Keyora serves the standard gRPC health service, `grpc.health.v1.Health`. `Check` with
an empty service name, or with the full name of a Keyora service such as
`keyora.v1.AuthService`, answers `SERVING` from the moment the listener is up. A
client following the status with `Watch` is told `NOT_SERVING` when shutdown begins.
The health service reports that the process is serving gRPC; it does not probe the
database. Use `GET /readyz` on the HTTP listener for that.

With `KEYORA_GRPC_REFLECTION=true`, Keyora serves gRPC server reflection, and generic
gRPC tools can list the services and call them without the proto files. Reflection
describes the API and nothing else; the proto files are public anyway. Set it to
`false` to serve only the Keyora services and the health service.

## Clients in other languages

The proto files are all a code generator needs. They import nothing outside the
`keyora/v1` directory except `google/protobuf/timestamp.proto`, which ships with
`protoc`.

```sh
protoc --proto_path=transport/grpc/proto \
       --<language>_out=<directory> \
       transport/grpc/proto/keyora/v1/*.proto
```

- That command generates the message types. The service stubs come from the gRPC
  plugin of your language, which adds its own `--…_out` option to the same command;
  see the documentation of your language's gRPC library for its name.
- The files use proto3 `optional` fields. `protoc` accepts those without extra flags
  from version 3.15.
- Error details are `google.rpc.ErrorInfo` messages. Most gRPC libraries have a
  package with the `google.rpc` types; the Go one is used in the example above.

The Go code in `keyorapb` is generated with `transport/grpc/generate.sh`; the
[module's README](../transport/grpc/README.md) lists the tool versions. Of the other
languages, only message generation for Python and Java has been run against these
files (with `protoc` 3.15.8); no client in another language is part of Keyora's test
suite.

## Differences from the REST API

The operations and their rules are the same. The wire formats differ in these ways:

- **Unknown fields.** The REST API rejects a JSON body with an unknown field. Protobuf
  ignores fields it does not know, so a message from a newer client is accepted and
  the extra fields are dropped.
- **Fields that cannot be changed** are absent from the update messages instead of
  being rejected: a tenant's `slug`, an application's `type`, a user's `email` and
  password.
- **`limit`.** `0` means the default page size. REST rejects `limit=0`.
- **`SetRolePermissions`.** An empty `permissions` list removes all permissions from
  the role. REST requires the `permissions` member to be present, to tell an empty
  list from a forgotten one; protobuf cannot tell them apart.
- **OAuth RPCs.** `OAuthService.Token` and `OAuthService.UserInfo` return ordinary
  messages and report errors as every other RPC does, with a status and `ErrorInfo`.
  The REST endpoints use the OAuth 2.0 and OpenID Connect JSON formats instead.
- **Field names.** Token introspection and userinfo use descriptive names
  (`subject`, `tenant_id`, `session_id`, `issuer`, `expires_at`, `issued_at`) where
  REST uses the claim names (`sub`, `tid`, `sid`, `iss`, `exp`, `iat`), and the two
  times are timestamps rather than Unix seconds.
- **`Retry-After`.** The value of that REST header is `retry_after_seconds` in the
  error metadata.
- **CORS** does not exist in gRPC. Browser calls reach Keyora through a gateway, which
  passes the page's origin in the `origin` metadata key.
