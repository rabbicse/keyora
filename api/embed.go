// Package api embeds the OpenAPI description so the server can serve it.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3 description of the Keyora REST API.
//
//go:embed openapi.yaml
var OpenAPI []byte
