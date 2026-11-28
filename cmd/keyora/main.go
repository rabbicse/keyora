// Command keyora is the Keyora server.
//
// It lives in its own Go module so that the third-party code it links — the
// database drivers and the GraphQL and gRPC transports — stays out of the
// dependency-free core module.
package main

import (
	"os"

	"github.com/rabbicse/keyora/internal/server"
	graphqlapi "github.com/rabbicse/keyora/transport/graphql"
	grpcapi "github.com/rabbicse/keyora/transport/grpc"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver (PostgreSQL)
	_ "modernc.org/sqlite"             // registers the "sqlite" driver (pure Go, no cgo)
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// REST is built in. GraphQL is mounted on the HTTP listener; gRPC runs
	// its own listener when KEYORA_GRPC_ADDR is set.
	os.Exit(server.Main(os.Args[1:], version, os.Stdout, os.Stderr, graphqlapi.Extension(), grpcapi.Extension()))
}
