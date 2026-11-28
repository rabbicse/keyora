// Package graphqlapi exposes the Keyora service over GraphQL.
//
// It is a second transport next to the REST API in internal/httpapi: the
// same use cases, the same caller identification (access.Gate) and the same
// error vocabulary, reached through one endpoint. It contains no business
// rules. It lives in a module of its own because it needs a GraphQL engine,
// and the core module has no third-party dependencies.
package graphqlapi

import (
	_ "embed"
	"net/http"

	"github.com/rabbicse/keyora/internal/server"
)

// Schema is the GraphQL schema the handler serves, in schema definition
// language. It is the single source of truth: the resolvers are checked
// against it when the handler is built.
//
//go:embed schema.graphql
var Schema string

// Route is the ServeMux pattern the extension mounts the handler on.
const Route = "POST /graphql"

// Extension links the GraphQL transport into a Keyora binary:
//
//	server.Main(os.Args[1:], version, os.Stdout, os.Stderr, graphqlapi.Extension())
//
// It serves Route on the HTTP listener unless KEYORA_GRAPHQL_ENABLED is false.
func Extension() server.Extension {
	return server.Extension{
		Name: "graphql",
		HTTP: func(d server.Deps) (map[string]http.Handler, error) {
			if !d.Config.GraphQLEnabled {
				return nil, nil
			}
			h, err := NewHandler(d.Gate, d.Log, Options{Introspection: d.Config.GraphQLIntrospection})
			if err != nil {
				return nil, err
			}
			return map[string]http.Handler{Route: h}, nil
		},
	}
}
