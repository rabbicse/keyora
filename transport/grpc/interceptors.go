package grpcapi

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// The interceptors run in this order for every unary call:
//
//	identifyCall  request ID and client address
//	accessLog     one log line per call
//	recoverPanic  a panic becomes an internal error
//	statusErrors  errors become gRPC statuses
//	throttle      the limit on credential requests
//
// There are no streaming RPCs in the Keyora services.

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// call is what the interceptors establish about one call.
type call struct {
	requestID string
	ip        string
}

type callKey struct{}

func callFrom(ctx context.Context) call {
	c, _ := ctx.Value(callKey{}).(call)
	return c
}

// header returns the first value of a request metadata key, or "".
func header(ctx context.Context, key string) string {
	if v := metadata.ValueFromIncomingContext(ctx, key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// identifyCall gives the call a request ID, taken from x-request-id when the
// client sent a well-formed one, and resolves the client address. The ID is
// returned in the response header metadata.
func (a *api) identifyCall(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	id := header(ctx, "x-request-id")
	if !requestIDRe.MatchString(id) {
		id = security.NewID()
	}
	// SetHeader only fails outside a call or after the header has been sent.
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", id))
	return next(context.WithValue(ctx, callKey{}, call{requestID: id, ip: a.resolveIP(ctx)}), req)
}

// resolveIP returns the peer address, or the address appended by the reverse
// proxy when proxy headers are trusted. Only the right-most x-forwarded-for
// entry is used: everything to its left is supplied by the client.
func (a *api) resolveIP(ctx context.Context) string {
	if a.trustProxy {
		if xff := metadata.ValueFromIncomingContext(ctx, "x-forwarded-for"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

// accessLog writes one line per call. It never logs messages or metadata,
// which carry passwords and tokens.
func (a *api) accessLog(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	start := time.Now()
	resp, err := next(ctx, req)
	c := callFrom(ctx)
	a.log.Info("grpc request", "request_id", c.requestID, "method", info.FullMethod, "code", status.Code(err).String(),
		"duration_ms", time.Since(start).Milliseconds(), "ip", c.ip)
	return resp, err
}

// recoverPanic turns a panic in a handler into an opaque internal error. The
// panic and its stack go to the log, never to the client.
func (a *api) recoverPanic(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			a.log.Error("panic recovered", "request_id", callFrom(ctx).requestID, "method", info.FullMethod,
				"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
			resp, err = nil, statusOf(ctx, errInternal)
		}
	}()
	return next(ctx, req)
}

// statusErrors converts the error of a handler, or of an interceptor after
// it, into a gRPC status.
func (a *api) statusErrors(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	resp, err := next(ctx, req)
	if err != nil {
		return nil, a.toStatus(ctx, info.FullMethod, err)
	}
	return resp, nil
}

// credentialServices are the services whose RPCs take credentials: the ones
// that correspond to the REST routes under /api/v1/auth and /api/v1/oauth.
var credentialServices = []string{
	"/" + keyorapb.AuthService_ServiceDesc.ServiceName + "/",
	"/" + keyorapb.OAuthService_ServiceDesc.ServiceName + "/",
}

// throttle applies the per-address limit on credential requests. The budget
// is the gate's, so it is shared with the REST API.
func (a *api) throttle(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	for _, prefix := range credentialServices {
		if strings.HasPrefix(info.FullMethod, prefix) {
			if err := a.gate.Throttle(callFrom(ctx).ip); err != nil {
				return nil, err
			}
			break
		}
	}
	return next(ctx, req)
}
