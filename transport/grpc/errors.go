package grpcapi

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rabbicse/keyora/internal/domain"
)

// errorDomain is the ErrorInfo domain of every error Keyora reports.
const errorDomain = "keyora"

var errInternal = domain.E(domain.KindInternal, "internal_error", "an internal error occurred")

func codeFor(kind domain.Kind) codes.Code {
	switch kind {
	case domain.KindInvalid:
		return codes.InvalidArgument
	case domain.KindUnauthenticated:
		return codes.Unauthenticated
	case domain.KindForbidden:
		return codes.PermissionDenied
	case domain.KindNotFound:
		return codes.NotFound
	case domain.KindConflict:
		return codes.AlreadyExists
	case domain.KindLocked:
		return codes.FailedPrecondition
	case domain.KindRateLimited:
		return codes.ResourceExhausted
	}
	return codes.Internal
}

// toStatus maps an error to a gRPC status. Anything that is not a domain
// error is logged and reported as an opaque internal error, so internals
// never reach the client.
func (a *api) toStatus(ctx context.Context, method string, err error) error {
	var de *domain.Error
	if errors.As(err, &de) && de.Kind != domain.KindInternal {
		return statusOf(ctx, de)
	}
	if _, ok := status.FromError(err); ok {
		// Already a status: the health service answers with its own. Nothing
		// in Keyora's service layer produces one.
		return err
	}
	if cause := ctx.Err(); cause != nil && errors.Is(err, cause) {
		// The client went away or its deadline passed; nothing went wrong here.
		return status.FromContextError(cause).Err()
	}
	a.log.Error("unhandled error", "request_id", callFrom(ctx).requestID, "method", method, "error", err)
	return statusOf(ctx, errInternal)
}

// statusOf builds the status for a domain error. The stable error code
// travels in an ErrorInfo detail, as its reason, so that clients branch on
// the same codes the REST API uses; the error's details and the request ID
// are the ErrorInfo metadata.
func statusOf(ctx context.Context, de *domain.Error) error {
	md := make(map[string]string, len(de.Details)+1)
	for k, v := range de.Details {
		md[k] = v
	}
	md["request_id"] = callFrom(ctx).requestID
	st := status.New(codeFor(de.Kind), de.Message)
	if detailed, err := st.WithDetails(&errdetails.ErrorInfo{Reason: de.Code, Domain: errorDomain, Metadata: md}); err == nil {
		st = detailed
	}
	return st.Err()
}
