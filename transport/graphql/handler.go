package graphqlapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"strings"

	graphql "github.com/graph-gophers/graphql-go"
	gqlerrors "github.com/graph-gophers/graphql-go/errors"
	gqllog "github.com/graph-gophers/graphql-go/log"

	"github.com/rabbicse/keyora/internal/access"
	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/service"
)

// Limits on one request. They bound the work a single HTTP request can ask
// for; the credential rate limit is applied per field, in the resolvers.
const (
	// MaxBodyBytes caps the request body (query, variables and JSON framing).
	MaxBodyBytes = 1 << 20
	// MaxQueryBytes caps the GraphQL document itself.
	MaxQueryBytes = 16 << 10
	// MaxDepth caps field nesting. The schema's own types nest three levels
	// deep; the rest is room for introspection queries, whose types are
	// recursive.
	MaxDepth = 16
	// MaxSelections caps the fields of an operation after fragments are expanded.
	MaxSelections = 2000
	// MaxParallelism caps the resolvers of one query that run at the same
	// time. The fields of a mutation always run one after another.
	MaxParallelism = 4
)

// Options configures a handler.
type Options struct {
	// Introspection lets clients query the schema (__schema, __type). When
	// it is off, error messages also stop suggesting field and argument names.
	Introspection bool
}

// Handler serves GraphQL over HTTP POST with a JSON body.
type Handler struct {
	schema        *graphql.Schema
	log           *slog.Logger
	introspection bool
}

// NewHandler builds the handler. It fails if the resolvers do not match Schema.
//
// The handler relies on the REST API's middleware for the request ID and the
// caller's address, so it must be mounted with (*httpapi.API).Mount.
func NewHandler(gate *access.Gate, log *slog.Logger, opt Options) (*Handler, error) {
	h := &Handler{log: log, introspection: opt.Introspection}
	schema, err := graphql.ParseSchema(Schema, &resolver{gate: gate, svc: gate.Service()},
		graphql.UseStringDescriptions(),
		graphql.UseFieldResolvers(),
		graphql.DisableFieldSelections(),
		graphql.MaxDepth(MaxDepth),
		graphql.MaxQueryLength(MaxQueryBytes),
		graphql.MaxSelections(MaxSelections),
		graphql.MaxParallelism(MaxParallelism),
		graphql.RestrictIntrospection(func(context.Context) bool { return opt.Introspection }),
		graphql.Logger(gqllog.LoggerFunc(h.logPanic)),
		graphql.PanicHandler(panicHandler{}),
	)
	if err != nil {
		return nil, fmt.Errorf("graphql schema: %w", err)
	}
	h.schema = schema
	return h, nil
}

// caller is what the resolvers know about the HTTP request being served.
type caller struct {
	meta   service.Meta
	bearer string
	// basicID and basicSecret are the HTTP Basic credentials, when hasBasic.
	basicID, basicSecret string
	hasBasic             bool
	origin               string
}

type callerKey struct{}

func callerFrom(ctx context.Context) *caller {
	c, _ := ctx.Value(callerKey{}).(*caller)
	if c == nil {
		// Only reachable if a resolver ran outside ServeHTTP.
		panic("graphqlapi: resolver called without a request")
	}
	return c
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := &caller{meta: httpapi.RequestMeta(r), bearer: httpapi.BearerToken(r), origin: r.Header.Get("Origin")}
	c.basicID, c.basicSecret, c.hasBasic = r.BasicAuth()

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.reject(w, c, http.StatusMethodNotAllowed, domain.E(domain.KindInvalid, "method_not_allowed", "GraphQL requests must use POST"))
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		h.reject(w, c, http.StatusUnsupportedMediaType, domain.E(domain.KindInvalid, "unsupported_media_type", "Content-Type must be application/json"))
		return
	}

	var req struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	err := dec.Decode(&req)
	if err == nil {
		if _, tail := dec.Token(); tail != io.EOF {
			err = errors.New("trailing data")
		}
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		h.reject(w, c, http.StatusRequestEntityTooLarge, domain.E(domain.KindInvalid, "payload_too_large", "request body is too large"))
		return
	case err != nil:
		h.reject(w, c, http.StatusBadRequest, domain.E(domain.KindInvalid, "invalid_json",
			`request body must be a single JSON object: {"query": "...", "operationName": "...", "variables": {...}}`))
		return
	case strings.TrimSpace(req.Query) == "":
		h.reject(w, c, http.StatusBadRequest, domain.Invalid("query", "is required"))
		return
	}

	ctx := context.WithValue(r.Context(), callerKey{}, c)
	res := h.schema.Exec(ctx, req.Query, req.OperationName, req.Variables)
	for _, e := range res.Errors {
		h.present(e, c.meta.RequestID)
	}
	writeJSON(w, http.StatusOK, res)
}

// reject answers a request that never reached the GraphQL engine, in the
// same shape as an execution error.
func (h *Handler) reject(w http.ResponseWriter, c *caller, status int, de *domain.Error) {
	writeJSON(w, status, graphql.Response{Errors: []*gqlerrors.QueryError{
		{Message: de.Message, Extensions: extensions(de, c.meta.RequestID)},
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) logPanic(ctx context.Context, value any) {
	h.log.Error("panic recovered", "request_id", callerFrom(ctx).meta.RequestID, "transport", "graphql",
		"panic", fmt.Sprint(value), "stack", string(debug.Stack()))
}
