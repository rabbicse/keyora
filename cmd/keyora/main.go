// Command keyora is the Keyora server.
//
// It lives in its own Go module so that the database drivers it links are the
// only third-party code in the project, and none of it is in the core module.
package main

import (
	"os"

	"github.com/rabbicse/keyora/internal/server"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver (PostgreSQL)
	_ "modernc.org/sqlite"             // registers the "sqlite" driver (pure Go, no cgo)
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(server.Main(os.Args[1:], version, os.Stdout, os.Stderr))
}
