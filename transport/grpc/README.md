# Keyora gRPC transport

Go module `github.com/rabbicse/keyora/transport/grpc`, package `grpcapi`.

It serves the operations of Keyora's REST API (`/api/v1`) over gRPC, on a listener of
its own. It is a thin adapter: every RPC identifies the caller through
`internal/access` and makes one call into `internal/service`. There are no business
rules here.

User documentation: [docs/grpc.md](../../docs/grpc.md).

## Why a separate module

The core module has no third-party dependencies. gRPC needs `google.golang.org/grpc`
and `google.golang.org/protobuf`, so the transport lives in a module of its own and a
binary links it only if it wants it. `google.golang.org/genproto/googleapis/rpc` is
required directly as well, for the `ErrorInfo` error detail; gRPC depends on it anyway.

## Layout

| Path | Contents |
|---|---|
| `proto/keyora/v1/*.proto` | The API definition, package `keyora.v1`. The comments in these files are the API reference. |
| `keyorapb/` | Go code generated from the proto files. Committed. Imports only gRPC and protobuf. |
| `*.go` | The server: `server.go` (options, health, reflection, listener), `interceptors.go`, `errors.go`, `caller.go` (credentials from metadata), `convert.go` (domain values to messages), and one file per service area. |
| `generate.sh` | Regenerates `keyorapb/`. |

## Linking it into a binary

In the binary's `go.mod`:

```
require github.com/rabbicse/keyora/transport/grpc v0.0.0

replace github.com/rabbicse/keyora/transport/grpc => ../../transport/grpc
```

In its `main`:

```go
import grpcapi "github.com/rabbicse/keyora/transport/grpc"

os.Exit(server.Main(os.Args[1:], version, os.Stdout, os.Stderr, grpcapi.Extension()))
```

`Extension()` listens on `KEYORA_GRPC_ADDR` and does nothing when that is empty.
`NewServer(deps)` returns the configured `*grpc.Server` without a listener, for tests
and for binaries that serve it themselves.

## Using the generated client from Go

A client imports the generated package and nothing else from Keyora:

```go
import "github.com/rabbicse/keyora/transport/grpc/keyorapb"

auth := keyorapb.NewAuthServiceClient(conn)
```

There is a complete example in [docs/grpc.md](../../docs/grpc.md#a-go-client).

## Regenerating the code

```sh
./generate.sh        # or: go generate ./...   or, from the repository root: make proto
```

The script needs `protoc`, `protoc-gen-go` and `protoc-gen-go-grpc` on `PATH`. The
committed code was generated with:

| Tool | Version |
|---|---|
| `protoc` | 3.15.8 |
| `protoc-gen-go` | 1.26.0 |
| `protoc-gen-go-grpc` | 1.1.0 |

The first two versions are written into the header of every generated file, so
generating with other versions changes those headers, and possibly more. With the
versions above, running the script twice produces identical files.

The proto files use `optional` fields, which `protoc` supports without extra flags from
version 3.15.

The service code is generated with `require_unimplemented_servers=false`. The server
in this module therefore has to implement every RPC in the proto files, and the
compiler rejects it if one is missing.

## Tests

```sh
go test -race ./...
```

The tests run the real server on an in-memory connection (`bufconn`) and call it
through the generated client stubs. Two of them listen on an ephemeral TCP port on
127.0.0.1 to cover start-up and graceful shutdown.
