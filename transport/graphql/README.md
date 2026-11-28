# Keyora GraphQL transport

Go module `github.com/rabbicse/keyora/transport/graphql`, package `graphqlapi`.

It serves the operations of Keyora's REST API (`/api/v1`) as GraphQL on
`POST /graphql`. It is a thin adapter: every resolver identifies the caller
through `internal/access` and makes one call into `internal/service`. There are
no business rules here.

User documentation: [docs/graphql.md](../../docs/graphql.md).

## Why a separate module

The core module has no third-party dependencies. GraphQL needs an execution
engine, so the transport lives in a module of its own and a binary links it only
if it wants it. The one dependency is `github.com/graph-gophers/graphql-go`. Its
`go.mod` lists tracing libraries, but none of their packages are imported, so none
are compiled in or recorded in `go.sum`.

## Linking it into a binary

In the binary's `go.mod`:

```
require github.com/rabbicse/keyora/transport/graphql v0.0.0

replace github.com/rabbicse/keyora/transport/graphql => ../../transport/graphql
```

In its `main.go`:

```go
import graphqlapi "github.com/rabbicse/keyora/transport/graphql"

os.Exit(server.Main(os.Args[1:], version, os.Stdout, os.Stderr, graphqlapi.Extension()))
```

`Extension()` mounts the handler at `POST /graphql` behind the REST middleware
(request ID, security headers, CORS, panic recovery, metrics, access log). It
mounts nothing when `KEYORA_GRAPHQL_ENABLED=false`, and passes
`KEYORA_GRAPHQL_INTROSPECTION` to the handler.

To mount it yourself:

```go
api := httpapi.New(svc, cfg, log)
h, err := graphqlapi.NewHandler(api.Gate(), log, graphqlapi.Options{Introspection: true})
api.Mount(graphqlapi.Route, h)
```

The handler takes the request ID and the caller's address from that middleware,
so it must be mounted with `(*httpapi.API).Mount`, not served on its own.

## Layout

| File | Contents |
|---|---|
| `schema.graphql` | The schema, embedded as `graphqlapi.Schema`. The single source of truth. |
| `graphql.go` | `Schema`, `Route`, `Extension()`. |
| `handler.go` | HTTP handling, request limits, `NewHandler`. |
| `errors.go` | Mapping of errors to `extensions.code`; masking of internal errors. |
| `resolver.go` | Caller identification, rate limiting, pagination. |
| `resolvers_*.go` | One method per field, by area: auth, OAuth, self-service, management. |
| `types.go` | The structs the schema's types resolve from, and their conversion from domain values. |

## No code generation

Nothing is generated. `graphql-go` checks the resolvers against `schema.graphql`
by reflection when the handler is built, so a field without a resolver, or with
one of the wrong type, fails `NewHandler` (and every test) rather than a request.

To add a field: add it to `schema.graphql`, add a method of the same name to
`resolver`, and add it to the lists in `security_test.go` (a test fails if a
management or credential field is missing from them).

## Tests

```
go test ./...
go test -race ./...
```

The tests drive the handler through `httpapi.New` and `Mount` on an
`httptest.Server`, so the middleware is part of what is tested.
