package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// The API definition, grouped by how its callers are identified.
var (
	credentialFiles = []protoreflect.FileDescriptor{keyorapb.File_keyora_v1_auth_proto, keyorapb.File_keyora_v1_oauth_proto}
	accountFiles    = []protoreflect.FileDescriptor{keyorapb.File_keyora_v1_account_proto}
	managementFiles = []protoreflect.FileDescriptor{
		keyorapb.File_keyora_v1_tenant_proto, keyorapb.File_keyora_v1_application_proto, keyorapb.File_keyora_v1_user_proto,
		keyorapb.File_keyora_v1_role_proto, keyorapb.File_keyora_v1_session_proto, keyorapb.File_keyora_v1_audit_proto,
	}
	allFiles = append(append(append([]protoreflect.FileDescriptor{keyorapb.File_keyora_v1_types_proto},
		credentialFiles...), accountFiles...), managementFiles...)
)

// methodsOf lists every RPC defined in the given files.
func methodsOf(files []protoreflect.FileDescriptor) []protoreflect.MethodDescriptor {
	var out []protoreflect.MethodDescriptor
	for _, f := range files {
		for i := 0; i < f.Services().Len(); i++ {
			ms := f.Services().Get(i).Methods()
			for j := 0; j < ms.Len(); j++ {
				out = append(out, ms.Get(j))
			}
		}
	}
	return out
}

func fullMethod(m protoreflect.MethodDescriptor) string {
	return "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
}

// invoke calls an RPC with a request that is empty apart from tenant_id,
// when the request has such a field. It is enough to reach the access check
// of any RPC, which is what the tests using it are about.
func (h *harness) invoke(ctx context.Context, m protoreflect.MethodDescriptor, tenantID string) error {
	req := dynamicpb.NewMessage(m.Input())
	if fd := m.Input().Fields().ByName("tenant_id"); fd != nil {
		req.Set(fd, protoreflect.ValueOfString(tenantID))
	}
	return h.conn.Invoke(ctx, fullMethod(m), req, dynamicpb.NewMessage(m.Output()))
}

func TestPrivilegeChecks(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")
	uid, tok := h.user(c, "mallory@example.com")
	mallory := h.bearer(tok.GetAccessToken())
	adminRole := h.adminRole(tid)

	management := methodsOf(managementFiles)
	if len(management) != 31 {
		t.Fatalf("the management API has %d RPCs, want 31", len(management))
	}
	// An ordinary user is refused by every management RPC of their own
	// tenant, and so is anyone without a valid credential.
	for _, m := range management {
		t.Run(string(m.Name()), func(t *testing.T) {
			expect(t, h.invoke(mallory, m, tid), codes.PermissionDenied, "forbidden")
			expect(t, h.invoke(h.ctx(), m, tid), codes.Unauthenticated, "unauthenticated")
			expect(t, h.invoke(h.bearer("not-a-token"), m, tid), codes.Unauthenticated, "invalid_token")
			expect(t, h.invoke(h.bearer(adminKey+"x"), m, tid), codes.Unauthenticated, "invalid_token")
			// Application credentials are not a management credential.
			expect(t, h.invoke(h.basic(c), m, tid), codes.Unauthenticated, "unauthenticated")
		})
	}
	// The account RPCs need a user: the root key has no user identity.
	for _, m := range methodsOf(accountFiles) {
		t.Run(string(m.Name()), func(t *testing.T) {
			expect(t, h.invoke(h.root(), m, ""), codes.PermissionDenied, "forbidden")
			expect(t, h.invoke(h.ctx(), m, ""), codes.Unauthenticated, "unauthenticated")
			expect(t, h.invoke(h.bearer("not-a-token"), m, ""), codes.Unauthenticated, "invalid_token")
		})
	}

	// Self-promotion, with real IDs.
	_, err := h.users.AssignUserRole(mallory, &keyorapb.AssignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: adminRole})
	expect(t, err, codes.PermissionDenied, "forbidden")
	_, err = h.roles.CreateRole(mallory, &keyorapb.CreateRoleRequest{TenantId: tid, Name: "god", Permissions: []string{"keyora:admin"}})
	expect(t, err, codes.PermissionDenied, "forbidden")
	verified := true
	_, err = h.users.UpdateUser(mallory, &keyorapb.UpdateUserRequest{TenantId: tid, Id: uid, EmailVerified: &verified})
	expect(t, err, codes.PermissionDenied, "forbidden")
	if me := must(h.account.GetMe(mallory, &keyorapb.GetMeRequest{}))(t); len(me.GetRoles()) != 0 || len(me.GetPermissions()) != 0 || me.GetUser().GetEmailVerified() {
		t.Fatalf("user gained privileges: %v", me)
	}

	// Once promoted by root, the same token works immediately (roles are
	// read live) and stops working the moment the role is taken away.
	h.makeAdmin(tid, uid)
	must(h.users.ListUsers(mallory, &keyorapb.ListUsersRequest{TenantId: tid}))(t)
	must(h.tenants.GetTenant(mallory, &keyorapb.GetTenantRequest{TenantId: tid}))(t)
	// A tenant administrator is still not root.
	_, err = h.tenants.CreateTenant(mallory, &keyorapb.CreateTenantRequest{Slug: "mine", Name: "Mine"})
	expect(t, err, codes.PermissionDenied, "forbidden")
	_, err = h.tenants.ListTenants(mallory, &keyorapb.ListTenantsRequest{})
	expect(t, err, codes.PermissionDenied, "forbidden")
	suspended := "suspended"
	_, err = h.tenants.UpdateTenant(mallory, &keyorapb.UpdateTenantRequest{TenantId: tid, Status: &suspended})
	expect(t, err, codes.PermissionDenied, "forbidden")
	must(h.users.UnassignUserRole(h.root(), &keyorapb.UnassignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: adminRole}))(t)
	_, err = h.users.ListUsers(mallory, &keyorapb.ListUsersRequest{TenantId: tid})
	expect(t, err, codes.PermissionDenied, "forbidden")
}

func TestRootAccessDisabledWithoutAdminKey(t *testing.T) {
	h := newHarness(t, func(s *setup) { s.adminKey = "" })
	_, err := h.tenants.ListTenants(h.ctx(), &keyorapb.ListTenantsRequest{})
	expect(t, err, codes.Unauthenticated, "unauthenticated")
	_, err = h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.tenants.ListTenants(h.bearer(""), &keyorapb.ListTenantsRequest{})
	expect(t, err, codes.Unauthenticated, "unauthenticated")
}

func TestCrossTenantAccessIsDenied(t *testing.T) {
	h := newHarness(t, nil)
	tidA, clientA := h.tenant("acme")
	tidB, clientB := h.tenant("beta")
	adminID, adminTok := h.user(clientA, "admin@example.com")
	h.makeAdmin(tidA, adminID)
	victim, victimTok := h.user(clientB, "victim@example.com")
	admin := h.bearer(adminTok.GetAccessToken())
	appB := appID(t, h, tidB, clientB.id)
	sessB := victimTok.GetSessionId()

	must(h.users.ListUsers(admin, &keyorapb.ListUsersRequest{TenantId: tidA}))(t) // sanity: A's admin works in A

	// Tenant B named in the request: every management RPC refuses.
	for _, m := range methodsOf(managementFiles) {
		t.Run(string(m.Name()), func(t *testing.T) {
			expect(t, h.invoke(admin, m, tidB), codes.PermissionDenied, "forbidden")
		})
	}
	// The same with the IDs of real resources of tenant B.
	disabled := "disabled"
	for name, call := range map[string]func() error{
		"GetTenant": func() error {
			_, err := h.tenants.GetTenant(admin, &keyorapb.GetTenantRequest{TenantId: tidB})
			return err
		},
		"GetUser": func() error {
			_, err := h.users.GetUser(admin, &keyorapb.GetUserRequest{TenantId: tidB, Id: victim})
			return err
		},
		"DeleteUser": func() error {
			_, err := h.users.DeleteUser(admin, &keyorapb.DeleteUserRequest{TenantId: tidB, Id: victim})
			return err
		},
		"UpdateUser": func() error {
			_, err := h.users.UpdateUser(admin, &keyorapb.UpdateUserRequest{TenantId: tidB, Id: victim, Status: &disabled})
			return err
		},
		"CreateUser": func() error {
			_, err := h.users.CreateUser(admin, &keyorapb.CreateUserRequest{TenantId: tidB, Email: "plant@example.com", Password: password})
			return err
		},
		"RotateApplicationSecret": func() error {
			_, err := h.apps.RotateApplicationSecret(admin, &keyorapb.RotateApplicationSecretRequest{TenantId: tidB, Id: appB})
			return err
		},
		"RevokeSession": func() error {
			_, err := h.sessions.RevokeSession(admin, &keyorapb.RevokeSessionRequest{TenantId: tidB, Id: sessB})
			return err
		},
		"CreateRole": func() error {
			_, err := h.roles.CreateRole(admin, &keyorapb.CreateRoleRequest{TenantId: tidB, Name: "backdoor"})
			return err
		},
		"ListAuditEvents": func() error {
			_, err := h.audit.ListAuditEvents(admin, &keyorapb.ListAuditEventsRequest{TenantId: tidB})
			return err
		},
	} {
		t.Run(name+" with real IDs", func(t *testing.T) { expect(t, call(), codes.PermissionDenied, "forbidden") })
	}

	// Own tenant in the request, tenant B's IDs in the rest: not found.
	for name, call := range map[string]func() error{
		"GetUser": func() error {
			_, err := h.users.GetUser(admin, &keyorapb.GetUserRequest{TenantId: tidA, Id: victim})
			return err
		},
		"DeleteUser": func() error {
			_, err := h.users.DeleteUser(admin, &keyorapb.DeleteUserRequest{TenantId: tidA, Id: victim})
			return err
		},
		"UnlockUser": func() error {
			_, err := h.users.UnlockUser(admin, &keyorapb.UnlockUserRequest{TenantId: tidA, Id: victim})
			return err
		},
		"UpdateUser": func() error {
			_, err := h.users.UpdateUser(admin, &keyorapb.UpdateUserRequest{TenantId: tidA, Id: victim, Status: &disabled})
			return err
		},
		"ListUserRoles": func() error {
			_, err := h.users.ListUserRoles(admin, &keyorapb.ListUserRolesRequest{TenantId: tidA, UserId: victim})
			return err
		},
		// A's admin role cannot be granted to B's user.
		"AssignUserRole": func() error {
			_, err := h.users.AssignUserRole(admin, &keyorapb.AssignUserRoleRequest{TenantId: tidA, UserId: victim, RoleId: h.adminRole(tidA)})
			return err
		},
		"GetApplication": func() error {
			_, err := h.apps.GetApplication(admin, &keyorapb.GetApplicationRequest{TenantId: tidA, Id: appB})
			return err
		},
		"DeleteApplication": func() error {
			_, err := h.apps.DeleteApplication(admin, &keyorapb.DeleteApplicationRequest{TenantId: tidA, Id: appB})
			return err
		},
		"RotateApplicationSecret": func() error {
			_, err := h.apps.RotateApplicationSecret(admin, &keyorapb.RotateApplicationSecretRequest{TenantId: tidA, Id: appB})
			return err
		},
		"RevokeSession": func() error {
			_, err := h.sessions.RevokeSession(admin, &keyorapb.RevokeSessionRequest{TenantId: tidA, Id: sessB})
			return err
		},
		"RevokeMySession": func() error {
			_, err := h.account.RevokeMySession(admin, &keyorapb.RevokeMySessionRequest{SessionId: sessB})
			return err
		},
	} {
		t.Run(name+" with foreign IDs", func(t *testing.T) { expect(t, call(), codes.NotFound, "not_found") })
	}

	// Tokens do not cross tenants through the auth RPCs either.
	_, err := h.auth.Refresh(h.basic(clientB), &keyorapb.RefreshRequest{RefreshToken: adminTok.GetRefreshToken()})
	expect(t, err, codes.Unauthenticated, "invalid_refresh_token")
	if in := must(h.auth.Introspect(h.basic(clientB), &keyorapb.IntrospectRequest{Token: adminTok.GetAccessToken()}))(t); in.GetActive() || in.GetSubject() != "" {
		t.Fatalf("tenant B introspected tenant A's token: %v", in)
	}
	_, err = h.auth.Login(h.basic(clientB), &keyorapb.LoginRequest{Email: "admin@example.com", Password: password})
	expect(t, err, codes.Unauthenticated, "invalid_credentials")

	// Nothing above harmed the victim.
	if me := must(h.account.GetMe(h.bearer(victimTok.GetAccessToken()), &keyorapb.GetMeRequest{}))(t); me.GetUser().GetStatus() != "active" {
		t.Fatalf("victim: %v", me)
	}
	if list := must(h.users.ListUsers(h.root(), &keyorapb.ListUsersRequest{TenantId: tidB}))(t); list.GetTotal() != 1 {
		t.Fatalf("tenant B's users changed: %v", list)
	}
	if list := must(h.roles.ListRoles(h.root(), &keyorapb.ListRolesRequest{TenantId: tidB}))(t); list.GetTotal() != 1 {
		t.Fatalf("tenant B's roles changed: %v", list)
	}
}

// TestNoStoredSecretInTheAPI checks the API definition itself: no message
// can carry a hash, and secrets and passwords only ever travel towards the
// server, except for the two responses that hand out a new client secret.
func TestNoStoredSecretInTheAPI(t *testing.T) {
	secretResponses := map[protoreflect.Name]bool{"CreateApplicationResponse": true, "RotateApplicationSecretResponse": true}
	seen := 0
	for _, f := range allFiles {
		for i := 0; i < f.Messages().Len(); i++ {
			msg := f.Messages().Get(i)
			isRequest := strings.HasSuffix(string(msg.Name()), "Request")
			for j := 0; j < msg.Fields().Len(); j++ {
				field := string(msg.Fields().Get(j).Name())
				switch {
				case strings.Contains(field, "hash"):
					t.Errorf("%s.%s: a hash must never be part of the API", msg.Name(), field)
				case strings.Contains(field, "secret") && !isRequest && !secretResponses[msg.Name()]:
					t.Errorf("%s.%s: only create and rotate may return a client secret", msg.Name(), field)
				case strings.Contains(field, "password") && !isRequest:
					t.Errorf("%s.%s: a password must never be returned", msg.Name(), field)
				}
				if field == "client_secret" && secretResponses[msg.Name()] {
					seen++
				}
			}
		}
	}
	if seen != len(secretResponses) {
		t.Fatalf("found client_secret in %d responses, want %d", seen, len(secretResponses))
	}
}

func TestCredentialRPCsAreThrottled(t *testing.T) {
	clock := testutil.NewClock() // stands still unless advanced
	limiter := ratelimit.New(60, 5)
	limiter.SetClock(clock.Now)
	h := newHarness(t, func(s *setup) { s.limiter = limiter })
	_, c := h.tenant("acme")

	limited := 0
	for i := 0; i < 12; i++ {
		_, err := h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: "nope nope nope"})
		if status.Code(err) == codes.ResourceExhausted {
			limited++
			if md := expect(t, err, codes.ResourceExhausted, "rate_limited"); md["retry_after_seconds"] == "" {
				t.Fatalf("rate limit error has no retry_after_seconds: %v", md)
			}
		} else {
			expect(t, err, codes.Unauthenticated, "invalid_credentials")
		}
	}
	if limited != 7 {
		t.Fatalf("%d of 12 calls were limited, want 7 (burst of 5)", limited)
	}

	// With the budget spent, every RPC that takes credentials is refused
	// before it looks at them...
	credential := methodsOf(credentialFiles)
	if len(credential) != 12 {
		t.Fatalf("AuthService and OAuthService have %d RPCs, want 12", len(credential))
	}
	for _, m := range credential {
		t.Run(string(m.Name()), func(t *testing.T) {
			expect(t, h.invoke(h.basic(c), m, ""), codes.ResourceExhausted, "rate_limited")
		})
	}
	// ...and nothing else is limited.
	for _, m := range append(methodsOf(accountFiles), methodsOf(managementFiles)...) {
		t.Run(string(m.Name()), func(t *testing.T) {
			expect(t, h.invoke(h.ctx(), m, ""), codes.Unauthenticated, "unauthenticated")
		})
	}
	must(h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{}))(t)
	must(healthpb.NewHealthClient(h.conn).Check(h.ctx(), &healthpb.HealthCheckRequest{}))(t)

	// The budget refills with time.
	clock.Advance(time.Minute)
	_, err := h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: "nope nope nope"})
	expect(t, err, codes.Unauthenticated, "invalid_credentials")
}

// faultyStore is a store whose tenant listing can be made to fail, panic,
// hang until the call is abandoned, or wait until released, to see what the
// transport does with it.
type faultyStore struct {
	store.Store
	mode    atomic.Value  // "", "fail", "panic", "hang" or "wait"
	entered chan struct{} // receives when a "wait" call has started
	release chan struct{} // closed to let "wait" calls finish
}

func newFaultyStore() *faultyStore {
	return &faultyStore{Store: memory.New(), entered: make(chan struct{}, 1), release: make(chan struct{})}
}

const internalDetail = "pq: connection to db.internal:5432 refused"

func (s *faultyStore) ListTenants(ctx context.Context, p store.Page) ([]*domain.Tenant, int, error) {
	switch s.mode.Load() {
	case "fail":
		return nil, 0, errors.New(internalDetail)
	case "panic":
		panic(internalDetail)
	case "hang":
		<-ctx.Done()
		return nil, 0, ctx.Err()
	case "wait":
		s.entered <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
	return s.Store.ListTenants(ctx, p)
}

func TestInternalErrorsAreMasked(t *testing.T) {
	st := newFaultyStore()
	h := newHarness(t, func(s *setup) { s.store = st })
	list := func(ctx context.Context) error {
		_, err := h.tenants.ListTenants(ctx, &keyorapb.ListTenantsRequest{})
		return err
	}
	opaque := func(t *testing.T, err error) {
		t.Helper()
		md := expect(t, err, codes.Internal, "internal_error")
		if status.Convert(err).Message() != "an internal error occurred" || strings.Contains(err.Error(), "db.internal") || md["request_id"] == "" {
			t.Fatalf("internal error is not opaque: %v %v", err, md)
		}
	}

	t.Run("error", func(t *testing.T) {
		st.mode.Store("fail")
		opaque(t, list(h.ctx("authorization", "Bearer "+adminKey, "x-request-id", "trace-fail")))
		recs := h.logs.records(t, "unhandled error")
		if len(recs) != 1 || recs[0]["error"] != internalDetail || recs[0]["request_id"] != "trace-fail" ||
			recs[0]["method"] != "/keyora.v1.TenantService/ListTenants" || recs[0]["level"] != "ERROR" {
			t.Fatalf("the cause was not logged: %v", recs)
		}
	})

	t.Run("panic", func(t *testing.T) {
		st.mode.Store("panic")
		opaque(t, list(h.ctx("authorization", "Bearer "+adminKey, "x-request-id", "trace-panic")))
		recs := h.logs.records(t, "panic recovered")
		if len(recs) != 1 || recs[0]["panic"] != internalDetail || recs[0]["request_id"] != "trace-panic" || recs[0]["stack"] == "" {
			t.Fatalf("the panic was not logged: %v", recs)
		}
		// The server survived.
		st.mode.Store("")
		if err := list(h.root()); err != nil {
			t.Fatalf("server did not survive a panic: %v", err)
		}
	})

	t.Run("caller gives up", func(t *testing.T) {
		st.mode.Store("hang")
		before := len(h.logs.records(t, "unhandled error"))
		ctx, cancel := context.WithTimeout(h.ctx("authorization", "Bearer "+adminKey, "x-request-id", "trace-hang"), 100*time.Millisecond)
		defer cancel()
		if err := list(ctx); status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("got %v, want DeadlineExceeded", err)
		}
		// The server sees the call end, and does not report it as its own failure.
		var rec map[string]any
		for deadline := time.Now().Add(5 * time.Second); rec == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			for _, r := range h.logs.records(t, "grpc request") {
				if r["request_id"] == "trace-hang" {
					rec = r
				}
			}
		}
		if rec == nil || (rec["code"] != "DeadlineExceeded" && rec["code"] != "Canceled") {
			t.Fatalf("access log of the abandoned call: %v", rec)
		}
		if len(h.logs.records(t, "unhandled error")) != before {
			t.Fatal("an abandoned call was logged as an internal error")
		}
	})
}
