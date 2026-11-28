package grpcapi_test

import (
	"context"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	grpcapi "github.com/rabbicse/keyora/transport/grpc"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

func TestHealthService(t *testing.T) {
	h := newHarness(t, nil)
	health := healthpb.NewHealthClient(h.conn)
	for _, service := range []string{"", "keyora.v1.AuthService", "keyora.v1.AuditService", "grpc.health.v1.Health"} {
		res := must(health.Check(h.ctx(), &healthpb.HealthCheckRequest{Service: service}))(t)
		if res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("health of %q: %v", service, res.GetStatus())
		}
	}
	if _, err := health.Check(h.ctx(), &healthpb.HealthCheckRequest{Service: "keyora.v1.NoSuchService"}); status.Code(err) != codes.NotFound {
		t.Fatalf("health of an unknown service: %v", err)
	}
}

// listServices asks the server reflection service which services exist.
func listServices(h *harness) ([]string, error) {
	stream, err := reflectionpb.NewServerReflectionClient(h.conn).ServerReflectionInfo(h.ctx())
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{},
	}); err != nil {
		return nil, err
	}
	res, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range res.GetListServicesResponse().GetService() {
		names = append(names, s.GetName())
	}
	return names, stream.CloseSend()
}

func TestReflection(t *testing.T) {
	on := newHarness(t, func(s *setup) { s.cfg.GRPCReflection = true })
	names, err := listServices(on)
	if err != nil {
		t.Fatalf("reflection is on but does not answer: %v", err)
	}
	// Every service of the API definition is being served.
	served := strings.Join(names, " ")
	want := 0
	for _, f := range allFiles {
		for i := 0; i < f.Services().Len(); i++ {
			want++
			if name := string(f.Services().Get(i).FullName()); !strings.Contains(served, name) {
				t.Errorf("%s is defined but not served", name)
			}
		}
	}
	if want != 9 || !strings.Contains(served, "grpc.health.v1.Health") {
		t.Fatalf("%d services defined, want 9; served: %s", want, served)
	}

	off := newHarness(t, nil)
	if _, err := listServices(off); status.Code(err) != codes.Unimplemented {
		t.Fatalf("reflection is off but answered: %v", err)
	}
}

func TestRequestID(t *testing.T) {
	h := newHarness(t, nil)
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	call := func(ctx context.Context) (id string, err error) {
		var header metadata.MD
		_, err = h.account.GetMe(ctx, &keyorapb.GetMeRequest{}, grpc.Header(&header))
		if v := header.Get("x-request-id"); len(v) == 1 {
			id = v[0]
		}
		return id, err
	}

	// A well-formed ID from the client is kept, and is also in the error.
	id, err := call(h.ctx("x-request-id", "trace-123"))
	if md := expect(t, err, codes.Unauthenticated, "unauthenticated"); id != "trace-123" || md["request_id"] != "trace-123" {
		t.Fatalf("inbound request id not echoed: header %q, error metadata %v", id, md)
	}
	// Without one, or with a hostile one, the server makes its own.
	for _, sent := range []string{"", "<script>alert(1)</script>", strings.Repeat("a", 65), "has space"} {
		ctx := h.ctx()
		if sent != "" {
			ctx = h.ctx("x-request-id", sent)
		}
		id, err := call(ctx)
		if md := expect(t, err, codes.Unauthenticated, "unauthenticated"); !uuid.MatchString(id) || md["request_id"] != id {
			t.Fatalf("sent %q: got header %q, error metadata %v", sent, id, md)
		}
	}
	// Successful calls carry it too, and it reaches the audit trail.
	var header metadata.MD
	tn := must(h.tenants.CreateTenant(h.ctx("authorization", "Bearer "+adminKey, "x-request-id", "trace-ok"),
		&keyorapb.CreateTenantRequest{Slug: "acme", Name: "Acme"}, grpc.Header(&header)))(t)
	if got := header.Get("x-request-id"); len(got) != 1 || got[0] != "trace-ok" {
		t.Fatalf("request id of a successful call: %v", got)
	}
	events := must(h.audit.ListAuditEvents(h.root(), &keyorapb.ListAuditEventsRequest{TenantId: tn.GetTenant().GetId(), Type: "tenant.created"}))(t)
	if len(events.GetEvents()) != 1 || events.GetEvents()[0].GetRequestId() != "trace-ok" {
		t.Fatalf("audit event: %v", events)
	}
}

func TestAccessLog(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.tenant("acme")
	must(h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: "ada@example.com", Password: password}))(t)
	login := must(h.auth.Login(h.ctx("authorization", basicValue(c), "x-request-id", "trace-login"),
		&keyorapb.LoginRequest{Email: "ada@example.com", Password: password}))(t)
	_, err := h.auth.Login(h.ctx("authorization", basicValue(c), "x-request-id", "trace-bad"),
		&keyorapb.LoginRequest{Email: "ada@example.com", Password: "a wrong password"})
	expect(t, err, codes.Unauthenticated, "invalid_credentials")
	must(h.account.GetMe(h.bearer(login.GetTokens().GetAccessToken()), &keyorapb.GetMeRequest{}))(t)

	byID := map[string]map[string]any{}
	for _, rec := range h.logs.records(t, "grpc request") {
		byID[rec["request_id"].(string)] = rec
	}
	ok, bad := byID["trace-login"], byID["trace-bad"]
	if ok["method"] != "/keyora.v1.AuthService/Login" || ok["code"] != "OK" || ok["ip"] != "bufconn" || ok["level"] != "INFO" {
		t.Fatalf("log record of the login: %v", ok)
	}
	if _, timed := ok["duration_ms"].(float64); !timed {
		t.Fatalf("log record has no duration: %v", ok)
	}
	if bad["method"] != "/keyora.v1.AuthService/Login" || bad["code"] != "Unauthenticated" {
		t.Fatalf("log record of the failed login: %v", bad)
	}
	// Nothing secret is ever logged.
	logged := h.logs.String()
	for name, secret := range map[string]string{
		"password": password, "wrong password": "a wrong password", "client secret": c.secret,
		"basic credentials": strings.TrimPrefix(basicValue(c), "Basic "),
		"access token":      login.GetTokens().GetAccessToken(), "refresh token": login.GetTokens().GetRefreshToken(),
		"email": "ada@example.com",
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}

func TestClientAddress(t *testing.T) {
	// ipOf registers a user with the given x-forwarded-for values and
	// returns the address recorded for the call.
	ipOf := func(t *testing.T, trust bool, forwarded ...string) string {
		h := newHarness(t, func(s *setup) { s.cfg.TrustProxyHeaders = trust })
		tid, c := h.tenant("acme")
		kv := []string{"authorization", basicValue(c)}
		for _, v := range forwarded {
			kv = append(kv, "x-forwarded-for", v)
		}
		must(h.auth.Register(h.ctx(kv...), &keyorapb.RegisterRequest{Email: "a@example.com", Password: password}))(t)
		events := must(h.audit.ListAuditEvents(h.root(), &keyorapb.ListAuditEventsRequest{TenantId: tid, Type: "user.registered"}))(t)
		return events.GetEvents()[0].GetIp()
	}
	// The peer address of the in-memory test connection is "bufconn".
	if ip := ipOf(t, false, "9.9.9.9, 10.0.0.7"); ip != "bufconn" {
		t.Fatalf("x-forwarded-for was honoured without TrustProxyHeaders: %s", ip)
	}
	if ip := ipOf(t, true, "9.9.9.9, 10.0.0.7"); ip != "10.0.0.7" {
		t.Fatalf("should use the right-most (proxy-appended) address, never the client-supplied one: %s", ip)
	}
	if ip := ipOf(t, true, "9.9.9.9", "8.8.8.8, 10.0.0.8"); ip != "10.0.0.8" {
		t.Fatalf("with several x-forwarded-for values the last one is the proxy's: %s", ip)
	}
	if ip := ipOf(t, true, "not an address"); ip != "bufconn" {
		t.Fatalf("an unusable x-forwarded-for should fall back to the peer address: %s", ip)
	}
	if ip := ipOf(t, true); ip != "bufconn" {
		t.Fatalf("no x-forwarded-for should fall back to the peer address: %s", ip)
	}
}

func TestMessageSizeLimit(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")
	// Just under 1 MiB reaches the service, which rejects the name.
	_, err := h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: "a@example.com", Password: password, Name: strings.Repeat("x", 1<<20-1024)})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	// Over 1 MiB is refused by the server before any handler runs.
	_, err = h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: "b@example.com", Password: password, Name: strings.Repeat("x", 1<<20+1)})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "larger than max") {
		t.Fatalf("oversized message: %v", err)
	}
	if list := must(h.users.ListUsers(h.root(), &keyorapb.ListUsersRequest{TenantId: tid}))(t); list.GetTotal() != 0 {
		t.Fatalf("a refused request created a user: %v", list)
	}
}

func TestExtensionIsOffWithoutAnAddress(t *testing.T) {
	ext := grpcapi.Extension()
	if ext.Name != "grpc" || ext.Serve == nil || ext.HTTP != nil {
		t.Fatalf("extension: %+v", ext)
	}
	d, _, logs := deps(t, nil) // GRPCAddr is empty
	done := make(chan error, 1)
	go func() { done <- ext.Serve(context.Background(), d) }() // never cancelled
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return at once although no address is configured")
	}
	if logs.String() != "" {
		t.Fatalf("a switched-off transport should stay silent: %s", logs.String())
	}
}

func TestExtensionReportsAListenFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	d, _, _ := deps(t, func(s *setup) { s.cfg.GRPCAddr = taken.Addr().String() })
	if err := grpcapi.Extension().Serve(t.Context(), d); err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("Serve on a taken address: %v", err)
	}
}

// serveExtension runs the extension on an ephemeral TCP port and returns a
// client connected to it, the function that stops it, and the channel that
// receives Serve's result.
func serveExtension(t *testing.T, st *faultyStore, shutdownTimeout time.Duration) (h *harness, stop context.CancelFunc, done chan error) {
	t.Helper()
	d, env, logs := deps(t, func(s *setup) {
		s.store = st
		s.cfg.GRPCAddr = "127.0.0.1:0"
		s.cfg.ShutdownTimeout = shutdownTimeout
	})
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	done = make(chan error, 1)
	go func() { done <- grpcapi.Extension().Serve(ctx, d) }()

	// The transport says where it listens.
	var addr string
	for deadline := time.Now().Add(5 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if recs := logs.records(t, "grpc is listening"); len(recs) == 1 {
			addr, _ = recs[0]["addr"].(string)
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if n, _ := strconv.Atoi(port); err != nil || host != "127.0.0.1" || n == 0 {
		t.Fatalf("no usable listening address was logged: %q", addr)
	}
	return connect(t, env, logs, addr), stop, done
}

func waitFor(t *testing.T, done chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("Serve did not return within %v", within)
		return nil
	}
}

func TestExtensionServesAndStopsGracefully(t *testing.T) {
	st := newFaultyStore()
	h, stop, done := serveExtension(t, st, 10*time.Second)

	// A real round trip over TCP.
	res := must(healthpb.NewHealthClient(h.conn).Check(h.ctx(), &healthpb.HealthCheckRequest{}))(t)
	if res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health: %v", res.GetStatus())
	}
	tid, c := h.tenant("acme")
	_, tok := h.user(c, "ada@example.com")
	if me := must(h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{}))(t); me.GetUser().GetTenantId() != tid {
		t.Fatalf("profile: %v", me)
	}
	if sessions := must(h.account.ListMySessions(h.bearer(tok.GetAccessToken()), &keyorapb.ListMySessionsRequest{}))(t); sessions.GetSessions()[0].GetIp() != "127.0.0.1" {
		t.Fatalf("the peer address was not recorded: %v", sessions)
	}

	// Shutdown waits for a call that is in progress...
	st.mode.Store("wait")
	inFlight := make(chan error, 1)
	go func() {
		_, err := h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{})
		inFlight <- err
	}()
	<-st.entered
	stop()
	select {
	case err := <-done:
		t.Fatalf("Serve returned (%v) while a call was still in progress", err)
	case <-time.After(200 * time.Millisecond):
	}
	// ...and ends once it has finished.
	close(st.release)
	if err := <-inFlight; err != nil {
		t.Fatalf("the call in progress was cut off by shutdown: %v", err)
	}
	if err := waitFor(t, done, 5*time.Second); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// The listener is gone.
	ctx, cancel := context.WithTimeout(h.ctx(), 2*time.Second)
	defer cancel()
	if _, err := h.tenants.ListTenants(ctx, &keyorapb.ListTenantsRequest{}); status.Code(err) != codes.Unavailable && status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("call after shutdown: %v", err)
	}
}

func TestExtensionShutdownIsBounded(t *testing.T) {
	st := newFaultyStore()
	h, stop, done := serveExtension(t, st, 300*time.Millisecond)

	// A client that follows the health status is told when shutdown begins.
	watch := must(healthpb.NewHealthClient(h.conn).Watch(h.ctx(), &healthpb.HealthCheckRequest{}))(t)
	if res := must(watch.Recv())(t); res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health before shutdown: %v", res.GetStatus())
	}

	// A call that never finishes on its own must not hold shutdown up for
	// longer than the shutdown timeout.
	st.mode.Store("wait")
	inFlight := make(chan error, 1)
	go func() {
		_, err := h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{})
		inFlight <- err
	}()
	<-st.entered
	start := time.Now()
	stop()
	if res := must(watch.Recv())(t); res.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("health during shutdown: %v", res.GetStatus())
	}
	if err := waitFor(t, done, 5*time.Second); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if waited := time.Since(start); waited < 250*time.Millisecond {
		t.Fatalf("shutdown did not give the call its %v: returned after %v", 300*time.Millisecond, waited)
	}
	if err := <-inFlight; status.Code(err) != codes.Unavailable && status.Code(err) != codes.Canceled {
		t.Fatalf("the abandoned call: %v", err)
	}
}

// TestGeneratedPackageIsSelfContained keeps keyorapb importable by clients:
// nothing but the standard library, gRPC and protobuf.
func TestGeneratedPackageIsSelfContained(t *testing.T) {
	files, err := filepath.Glob("keyorapb/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no generated files: %v", err)
	}
	for _, file := range files {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			std := !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
			if !std && !strings.HasPrefix(path, "google.golang.org/grpc") && !strings.HasPrefix(path, "google.golang.org/protobuf/") {
				t.Errorf("%s imports %s", file, path)
			}
		}
	}
}

func TestMetadataSizeLimit(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.account.GetMe(h.ctx("authorization", "Bearer "+strings.Repeat("x", 32<<10)), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.account.GetMe(h.ctx("authorization", "Bearer "+strings.Repeat("x", 100<<10)), &keyorapb.GetMeRequest{})
	// The server announces its limit and the client library refuses to send
	// more; either way no handler sees the call.
	if err == nil || errorInfo(err) != nil {
		t.Fatalf("oversized metadata reached a handler: %v", err)
	}
}
