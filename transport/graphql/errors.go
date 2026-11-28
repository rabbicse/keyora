package graphqlapi

import (
	"context"
	"errors"
	"strings"

	gqlerrors "github.com/graph-gophers/graphql-go/errors"

	"github.com/rabbicse/keyora/internal/domain"
)

// codeInvalidQuery marks a document the engine refused to execute: a syntax
// error, a validation error (unknown field, wrong argument type, too deep)
// or a limit on its size.
const codeInvalidQuery = "invalid_query"

var errInternal = domain.E(domain.KindInternal, "internal_error", "an internal error occurred")

// present rewrites one error of the engine into Keyora's error shape:
// extensions.code, extensions.request_id and, when there are any,
// extensions.details.
//
// A resolver error that is a domain.Error is shown as it is. Any other
// failure during execution is logged and reported as an opaque internal
// error, so internals never reach the client.
func (h *Handler) present(e *gqlerrors.QueryError, requestID string) {
	var de *domain.Error
	switch {
	case e.ResolverError != nil:
		if !errors.As(e.ResolverError, &de) {
			h.log.Error("unhandled error", "request_id", requestID, "transport", "graphql", "path", e.Path, "error", e.ResolverError)
			de = errInternal
		}
	case len(e.Path) > 0:
		// The engine itself failed at a field, for example because a resolver
		// returned nil for a non-null type. That is a defect, not a bad query.
		h.log.Error("execution error", "request_id", requestID, "transport", "graphql", "path", e.Path, "error", e.Message)
		de = errInternal
	default:
		// The engine refused the document; its message says why.
		msg := e.Message
		if !h.introspection {
			// "Did you mean ...?" would name parts of the schema nobody asked about.
			msg, _, _ = strings.Cut(msg, " Did you mean")
		}
		de = domain.E(domain.KindInvalid, codeInvalidQuery, msg)
	}
	e.Message = de.Message
	e.Extensions = extensions(de, requestID)
}

func extensions(de *domain.Error, requestID string) map[string]any {
	ext := map[string]any{"code": de.Code, "request_id": requestID}
	if len(de.Details) > 0 {
		ext["details"] = de.Details
	}
	return ext
}

// panicHandler reports a panic in a resolver as an internal error. The panic
// value is logged by Handler.logPanic and never shown.
type panicHandler struct{}

func (panicHandler) MakePanicError(context.Context, any) *gqlerrors.QueryError {
	return &gqlerrors.QueryError{Message: errInternal.Message, ResolverError: errInternal}
}
