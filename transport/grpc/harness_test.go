package grpcapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/rabbicse/keyora/internal/access"
	"github.com/rabbicse/keyora/internal/config"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/server"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	grpcapi "github.com/rabbicse/keyora/transport/grpc"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

const (
	adminKey = "test-admin-key-0123456789abcdef0123456789"
	password = "correct horse battery"
)

// setup is what a test may change before the server starts.
type setup struct {
	store    store.Store
	adminKey string
	limiter  *ratelimit.Limiter
	cfg      config.Config
}

type harness struct {
	t    *testing.T
	env  *testutil.Env
	logs *logBuffer
	conn *grpc.ClientConn

	auth     keyorapb.AuthServiceClient
	oauth    keyorapb.OAuthServiceClient
	account  keyorapb.AccountServiceClient
	tenants  keyorapb.TenantServiceClient
	apps     keyorapb.ApplicationServiceClient
	users    keyorapb.UserServiceClient
	roles    keyorapb.RoleServiceClient
	sessions keyorapb.SessionServiceClient
	audit    keyorapb.AuditServiceClient
}

// deps wires a service on the in-memory store the way server.Run does.
func deps(t *testing.T, mod func(*setup)) (server.Deps, *testutil.Env, *logBuffer) {
	t.Helper()
	s := setup{store: memory.New(), adminKey: adminKey, cfg: config.Config{ShutdownTimeout: 5 * time.Second}}
	if mod != nil {
		mod(&s)
	}
	env := testutil.NewEnv(t, s.store, nil)
	logs := &logBuffer{}
	return server.Deps{
		Service: env.Svc, Gate: access.New(env.Svc, s.adminKey, s.limiter), Config: &s.cfg,
		Log: slog.New(slog.NewJSONHandler(logs, nil)), Version: "test",
	}, env, logs
}

// newHarness serves the gRPC API on an in-memory connection.
func newHarness(t *testing.T, mod func(*setup)) *harness {
	t.Helper()
	d, env, logs := deps(t, mod)
	srv := grpcapi.NewServer(d)
	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return connect(t, env, logs, "passthrough:///keyora",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
}

// connect opens a client connection and the stubs of every service.
func connect(t *testing.T, env *testutil.Env, logs *logBuffer, target string, opts ...grpc.DialOption) *harness {
	t.Helper()
	conn, err := grpc.NewClient(target, append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &harness{
		t: t, env: env, logs: logs, conn: conn,
		auth: keyorapb.NewAuthServiceClient(conn), oauth: keyorapb.NewOAuthServiceClient(conn),
		account: keyorapb.NewAccountServiceClient(conn), tenants: keyorapb.NewTenantServiceClient(conn),
		apps: keyorapb.NewApplicationServiceClient(conn), users: keyorapb.NewUserServiceClient(conn),
		roles: keyorapb.NewRoleServiceClient(conn), sessions: keyorapb.NewSessionServiceClient(conn),
		audit: keyorapb.NewAuditServiceClient(conn),
	}
}

// ctx returns a call context carrying the given metadata key/value pairs.
func (h *harness) ctx(kv ...string) context.Context {
	return metadata.AppendToOutgoingContext(h.t.Context(), kv...)
}

// bearer authenticates a call with an access token or the admin key.
func (h *harness) bearer(token string) context.Context {
	return h.ctx("authorization", "Bearer "+token)
}

func (h *harness) root() context.Context { return h.bearer(adminKey) }

// client is an application's credentials.
type client struct{ id, secret string }

// basicValue is the HTTP Basic authorization value for an application.
func basicValue(c client) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.id+":"+c.secret))
}

// basic authenticates a call as an application.
func (h *harness) basic(c client) context.Context { return h.ctx("authorization", basicValue(c)) }

// tenant creates a tenant with one confidential application.
func (h *harness) tenant(slug string) (tenantID string, c client) {
	h.t.Helper()
	tn := must(h.tenants.CreateTenant(h.root(), &keyorapb.CreateTenantRequest{Slug: slug, Name: slug}))(h.t)
	tenantID = tn.GetTenant().GetId()
	app := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tenantID, Name: "web"}))(h.t)
	return tenantID, client{app.GetApplication().GetClientId(), app.GetClientSecret()}
}

// user registers and signs in, returning the user's ID and tokens.
func (h *harness) user(c client, email string) (userID string, tokens *keyorapb.Tokens) {
	h.t.Helper()
	reg := must(h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: email, Password: password, Name: "Ada"}))(h.t)
	login := must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: email, Password: password}))(h.t)
	return reg.GetUser().GetId(), login.GetTokens()
}

// adminRole returns the ID of the tenant's built-in administrator role.
func (h *harness) adminRole(tenantID string) string {
	h.t.Helper()
	list := must(h.roles.ListRoles(h.root(), &keyorapb.ListRolesRequest{TenantId: tenantID}))(h.t)
	for _, r := range list.GetRoles() {
		if r.GetName() == "keyora-admin" {
			return r.GetId()
		}
	}
	h.t.Fatal("tenant has no keyora-admin role")
	return ""
}

func (h *harness) makeAdmin(tenantID, userID string) {
	h.t.Helper()
	must(h.users.AssignUserRole(h.root(), &keyorapb.AssignUserRoleRequest{TenantId: tenantID, UserId: userID, RoleId: h.adminRole(tenantID)}))(h.t)
}

// must unwraps the result of a call that has to succeed:
//
//	res := must(client.Call(ctx, req))(t)
func must[T any](v T, err error) func(testing.TB) T {
	return func(t testing.TB) T {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return v
	}
}

// errorInfo returns the ErrorInfo detail of an error, or nil.
func errorInfo(err error) *errdetails.ErrorInfo {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info
		}
	}
	return nil
}

// expect checks the status code of err and the stable error code Keyora
// attached to it, and returns the error's metadata.
func expect(t testing.TB, err error, code codes.Code, reason string) map[string]string {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got %v, want code %v (%s)", err, code, reason)
	}
	info := errorInfo(err)
	if info == nil {
		t.Fatalf("error has no ErrorInfo detail: %v", err)
	}
	if info.GetReason() != reason || info.GetDomain() != "keyora" {
		t.Fatalf("got reason %q in domain %q, want %q in keyora (%v)", info.GetReason(), info.GetDomain(), reason, err)
	}
	return info.GetMetadata()
}

// logBuffer collects the server's JSON log lines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// records returns the log records with the given message.
func (b *logBuffer) records(t testing.TB, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}
