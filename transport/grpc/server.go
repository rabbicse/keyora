package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/rabbicse/keyora/internal/access"
	"github.com/rabbicse/keyora/internal/server"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

const (
	// maxRecvBytes bounds one request message, like the REST API's body limit.
	maxRecvBytes = 1 << 20
	// maxHeaderBytes bounds request metadata, like the HTTP listener's header limit.
	maxHeaderBytes = 64 << 10
)

// Extension links the gRPC transport into a Keyora binary. It serves on
// Config.GRPCAddr and is switched off when that address is empty.
func Extension() server.Extension {
	return server.Extension{Name: "grpc", Serve: listenAndServe}
}

// api implements every Keyora gRPC service on top of the service layer.
type api struct {
	svc        *service.Service
	gate       *access.Gate
	log        *slog.Logger
	trustProxy bool
}

// NewServer builds a gRPC server with every Keyora service, the standard
// health service and, when Config.GRPCReflection is set, server reflection.
// The caller serves it on a listener of its choice. d.Gate and d.Config are
// required.
func NewServer(d server.Deps) *grpc.Server {
	srv, _ := newServer(d)
	return srv
}

func logger(d server.Deps) *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}

func newServer(d server.Deps) (*grpc.Server, *health.Server) {
	a := &api{svc: d.Gate.Service(), gate: d.Gate, log: logger(d), trustProxy: d.Config.TrustProxyHeaders}

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvBytes),
		grpc.MaxHeaderListSize(maxHeaderBytes),
		// Clients may send keepalive pings, also on a connection with no call
		// in progress, but not more often than every 30 seconds.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second, PermitWithoutStream: true}),
		// Probe quiet connections so dead peers are noticed, and let go of
		// connections that have carried no call for a while.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 2 * time.Minute, Timeout: 20 * time.Second, MaxConnectionIdle: 15 * time.Minute,
		}),
		grpc.ChainUnaryInterceptor(a.identifyCall, a.accessLog, a.recoverPanic, a.statusErrors, a.throttle),
	)
	keyorapb.RegisterAuthServiceServer(srv, a)
	keyorapb.RegisterOAuthServiceServer(srv, a)
	keyorapb.RegisterAccountServiceServer(srv, a)
	keyorapb.RegisterTenantServiceServer(srv, a)
	keyorapb.RegisterApplicationServiceServer(srv, a)
	keyorapb.RegisterUserServiceServer(srv, a)
	keyorapb.RegisterRoleServiceServer(srv, a)
	keyorapb.RegisterSessionServiceServer(srv, a)
	keyorapb.RegisterAuditServiceServer(srv, a)

	// The empty service name, which is SERVING from the start, stands for the
	// server as a whole; each service can also be asked about by name.
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	for name := range srv.GetServiceInfo() {
		hs.SetServingStatus(name, healthpb.HealthCheckResponse_SERVING)
	}
	if d.Config.GRPCReflection {
		reflection.Register(srv)
	}
	return srv, hs
}

// listenAndServe is Extension.Serve: it does nothing when no address is
// configured, and otherwise serves until ctx is cancelled.
func listenAndServe(ctx context.Context, d server.Deps) error {
	addr := d.Config.GRPCAddr
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log := logger(d)
	srv, hs := newServer(d)
	log.Info("grpc is listening", "addr", ln.Addr().String(), "reflection", d.Config.GRPCReflection)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	// Calls in progress get the shutdown timeout to finish; what is still
	// open after that is cut off.
	hs.Shutdown()
	drained := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(drained)
	}()
	timeout := time.NewTimer(d.Config.ShutdownTimeout)
	defer timeout.Stop()
	select {
	case <-drained:
	case <-timeout.C:
		log.Warn("grpc: calls still open after the shutdown timeout were cut off")
		srv.Stop()
	}
	// ErrServerStopped means ctx was cancelled before Serve got going.
	if err := <-errc; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}
