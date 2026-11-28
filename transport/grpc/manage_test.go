package grpcapi_test

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

func TestTenantManagement(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")

	_, err := h.tenants.CreateTenant(h.root(), &keyorapb.CreateTenantRequest{Slug: "acme", Name: "Again"})
	expect(t, err, codes.AlreadyExists, "slug_taken")
	_, err = h.tenants.CreateTenant(h.root(), &keyorapb.CreateTenantRequest{Slug: "Not A Slug", Name: "x"})
	if md := expect(t, err, codes.InvalidArgument, "validation_failed"); md["slug"] == "" {
		t.Fatalf("validation error does not name the field: %v", md)
	}
	_, err = h.tenants.CreateTenant(h.root(), &keyorapb.CreateTenantRequest{Slug: "nameless"})
	expect(t, err, codes.InvalidArgument, "validation_failed")

	got := must(h.tenants.GetTenant(h.root(), &keyorapb.GetTenantRequest{TenantId: tid}))(t).GetTenant()
	if got.GetSlug() != "acme" || got.GetStatus() != "active" || got.GetCreatedAt() == nil {
		t.Fatalf("tenant: %v", got)
	}
	_, err = h.tenants.GetTenant(h.root(), &keyorapb.GetTenantRequest{TenantId: "unknown"})
	expect(t, err, codes.NotFound, "not_found")

	h.tenant("beta")
	if list := must(h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{}))(t); list.GetTotal() != 2 || len(list.GetTenants()) != 2 {
		t.Fatalf("tenants: %v", list)
	}
	if list := must(h.tenants.ListTenants(h.root(), &keyorapb.ListTenantsRequest{Limit: 1, Offset: 1}))(t); list.GetTotal() != 2 || len(list.GetTenants()) != 1 {
		t.Fatalf("paging: %v", list)
	}
	for _, bad := range []*keyorapb.ListTenantsRequest{{Limit: -1}, {Limit: 101}, {Offset: -1}} {
		_, err = h.tenants.ListTenants(h.root(), bad)
		expect(t, err, codes.InvalidArgument, "validation_failed")
	}

	// Only the fields that are set change.
	name := "Acme Corp"
	if upd := must(h.tenants.UpdateTenant(h.root(), &keyorapb.UpdateTenantRequest{TenantId: tid, Name: &name}))(t).GetTenant(); upd.GetName() != name || upd.GetStatus() != "active" {
		t.Fatalf("renamed tenant: %v", upd)
	}
	bogus := "bogus"
	_, err = h.tenants.UpdateTenant(h.root(), &keyorapb.UpdateTenantRequest{TenantId: tid, Status: &bogus})
	expect(t, err, codes.InvalidArgument, "validation_failed")

	// Suspending a tenant stops its applications at once.
	must(h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: "bob@example.com", Password: password}))(t)
	suspended := "suspended"
	if upd := must(h.tenants.UpdateTenant(h.root(), &keyorapb.UpdateTenantRequest{TenantId: tid, Status: &suspended}))(t).GetTenant(); upd.GetName() != name || upd.GetStatus() != suspended {
		t.Fatalf("suspended tenant: %v", upd)
	}
	_, err = h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "bob@example.com", Password: password})
	expect(t, err, codes.Unauthenticated, "invalid_client")
}

func TestApplicationManagement(t *testing.T) {
	h := newHarness(t, nil)
	tid, _ := h.tenant("acme")

	ttl := int64(300)
	created := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{
		TenantId: tid, Name: "api", RedirectUris: []string{"https://api.test/cb"},
		AccessTokenTtlSeconds: &ttl,
	}))(t)
	app, oldSecret := created.GetApplication(), created.GetClientSecret()
	if app.GetType() != "confidential" || !strings.HasPrefix(app.GetClientId(), "app_") || !strings.HasPrefix(oldSecret, "kys_") ||
		app.GetAccessTokenTtlSeconds() != 300 || app.GetRefreshTokenTtlSeconds() <= 300 ||
		strings.Join(app.GetRedirectUris(), ",") != "https://api.test/cb" || app.GetStatus() != "active" {
		t.Fatalf("created application: %v", created)
	}

	// Neither the secret nor its stored hash can be read back.
	stored, err := h.env.Store.GetApplication(t.Context(), tid, app.GetId())
	if err != nil || stored.ClientSecretHash == "" {
		t.Fatalf("stored application: %v %v", stored, err)
	}
	leaks := func(m proto.Message) bool {
		text := prototext.Format(m)
		return strings.Contains(text, oldSecret) || strings.Contains(text, stored.ClientSecretHash) || strings.Contains(text, "secret")
	}
	got := must(h.apps.GetApplication(h.root(), &keyorapb.GetApplicationRequest{TenantId: tid, Id: app.GetId()}))(t)
	if !proto.Equal(got.GetApplication(), app) || leaks(got) {
		t.Fatalf("read application: %v", got)
	}
	list := must(h.apps.ListApplications(h.root(), &keyorapb.ListApplicationsRequest{TenantId: tid, Limit: 1, Offset: 1}))(t)
	if list.GetTotal() != 2 || len(list.GetApplications()) != 1 || leaks(list) {
		t.Fatalf("listed applications: %v", list)
	}

	_, err = h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "api"})
	expect(t, err, codes.AlreadyExists, "name_taken")
	_, err = h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	_, err = h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "x", Type: "hybrid"})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	_, err = h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "x", RedirectUris: []string{"https://x.test/*"}})
	if md := expect(t, err, codes.InvalidArgument, "validation_failed"); md["redirect_uris"] == "" {
		t.Fatalf("validation error does not name the field: %v", md)
	}

	// A partial update changes only what is set, and a list that is set
	// replaces the stored one, also with nothing.
	name := "API"
	upd := must(h.apps.UpdateApplication(h.root(), &keyorapb.UpdateApplicationRequest{TenantId: tid, Id: app.GetId(), Name: &name,
		AllowedOrigins: &keyorapb.StringList{Values: []string{"https://api.test"}}}))(t)
	if a := upd.GetApplication(); a.GetName() != "API" || strings.Join(a.GetAllowedOrigins(), ",") != "https://api.test" ||
		strings.Join(a.GetRedirectUris(), ",") != "https://api.test/cb" ||
		a.GetAccessTokenTtlSeconds() != 300 || leaks(upd) {
		t.Fatalf("updated application: %v", upd)
	}
	upd = must(h.apps.UpdateApplication(h.root(), &keyorapb.UpdateApplicationRequest{TenantId: tid, Id: app.GetId(),
		RedirectUris: &keyorapb.StringList{}}))(t)
	if a := upd.GetApplication(); len(a.GetRedirectUris()) != 0 || a.GetName() != "API" || len(a.GetAllowedOrigins()) != 1 {
		t.Fatalf("cleared fields: %v", upd)
	}
	tooShort := int64(5)
	_, err = h.apps.UpdateApplication(h.root(), &keyorapb.UpdateApplicationRequest{TenantId: tid, Id: app.GetId(), AccessTokenTtlSeconds: &tooShort})
	expect(t, err, codes.InvalidArgument, "validation_failed")

	// Rotation returns a new secret and retires the old one at once.
	rot := must(h.apps.RotateApplicationSecret(h.root(), &keyorapb.RotateApplicationSecretRequest{TenantId: tid, Id: app.GetId()}))(t)
	if rot.GetClientSecret() == "" || rot.GetClientSecret() == oldSecret || rot.GetApplication().GetId() != app.GetId() {
		t.Fatalf("rotated secret: %v", rot)
	}
	login := &keyorapb.LoginRequest{Email: "a@b.co", Password: password}
	_, err = h.auth.Login(h.basic(client{app.GetClientId(), oldSecret}), login)
	expect(t, err, codes.Unauthenticated, "invalid_client")
	_, err = h.auth.Login(h.basic(client{app.GetClientId(), rot.GetClientSecret()}), login)
	expect(t, err, codes.Unauthenticated, "invalid_credentials")

	spa := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "spa", Type: "public"}))(t)
	_, err = h.apps.RotateApplicationSecret(h.root(), &keyorapb.RotateApplicationSecretRequest{TenantId: tid, Id: spa.GetApplication().GetId()})
	expect(t, err, codes.InvalidArgument, "not_confidential")

	must(h.apps.DeleteApplication(h.root(), &keyorapb.DeleteApplicationRequest{TenantId: tid, Id: app.GetId()}))(t)
	_, err = h.apps.DeleteApplication(h.root(), &keyorapb.DeleteApplicationRequest{TenantId: tid, Id: app.GetId()})
	expect(t, err, codes.NotFound, "not_found")
	_, err = h.apps.GetApplication(h.root(), &keyorapb.GetApplicationRequest{TenantId: tid, Id: app.GetId()})
	expect(t, err, codes.NotFound, "not_found")
}

func TestUserRoleAndSessionManagement(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")

	created := must(h.users.CreateUser(h.root(), &keyorapb.CreateUserRequest{TenantId: tid, Email: "Bob@Example.com", Password: password, Name: "Bob", EmailVerified: true}))(t)
	uid := created.GetUser().GetId()
	if u := created.GetUser(); u.GetEmail() != "bob@example.com" || !u.GetEmailVerified() || u.GetName() != "Bob" {
		t.Fatalf("created user: %v", u)
	}
	stored, err := h.env.Store.GetUser(t.Context(), tid, uid)
	if err != nil || stored.PasswordHash == "" {
		t.Fatalf("stored user: %v %v", stored, err)
	}
	leaks := func(m proto.Message) bool {
		text := prototext.Format(m)
		return strings.Contains(text, stored.PasswordHash) || strings.Contains(text, password) || strings.Contains(text, "hash")
	}
	if leaks(created) {
		t.Fatalf("created user leaks credential material: %v", created)
	}
	_, err = h.users.CreateUser(h.root(), &keyorapb.CreateUserRequest{TenantId: tid, Email: "bob@example.com", Password: password})
	expect(t, err, codes.AlreadyExists, "email_taken")
	_, err = h.users.CreateUser(h.root(), &keyorapb.CreateUserRequest{TenantId: tid, Email: "nope", Password: password})
	if md := expect(t, err, codes.InvalidArgument, "validation_failed"); md["email"] == "" {
		t.Fatalf("validation error does not name the field: %v", md)
	}

	if got := must(h.users.GetUser(h.root(), &keyorapb.GetUserRequest{TenantId: tid, Id: uid}))(t); !proto.Equal(got.GetUser(), created.GetUser()) || leaks(got) {
		t.Fatalf("read user: %v", got)
	}
	name := "Robert"
	if upd := must(h.users.UpdateUser(h.root(), &keyorapb.UpdateUserRequest{TenantId: tid, Id: uid, Name: &name}))(t); upd.GetUser().GetName() != name ||
		!upd.GetUser().GetEmailVerified() || upd.GetUser().GetStatus() != "active" || leaks(upd) {
		t.Fatalf("renamed user: %v", upd)
	}
	unverified := false
	if upd := must(h.users.UpdateUser(h.root(), &keyorapb.UpdateUserRequest{TenantId: tid, Id: uid, EmailVerified: &unverified}))(t); upd.GetUser().GetEmailVerified() ||
		upd.GetUser().GetName() != name {
		t.Fatalf("an optional field set to false was not applied: %v", upd)
	}

	// Disabling a user ends their sessions.
	login := must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "bob@example.com", Password: password}))(t)
	if list := must(h.sessions.ListSessions(h.root(), &keyorapb.ListSessionsRequest{TenantId: tid, UserId: uid, ActiveOnly: true}))(t); list.GetTotal() != 1 ||
		list.GetSessions()[0].GetId() != login.GetTokens().GetSessionId() || list.GetSessions()[0].GetUserId() != uid {
		t.Fatalf("sessions: %v", list)
	}
	disabled := "disabled"
	must(h.users.UpdateUser(h.root(), &keyorapb.UpdateUserRequest{TenantId: tid, Id: uid, Status: &disabled}))(t)
	_, err = h.account.GetMe(h.bearer(login.GetTokens().GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	if list := must(h.users.ListUsers(h.root(), &keyorapb.ListUsersRequest{TenantId: tid, Status: "disabled", Email: "BOB"}))(t); list.GetTotal() != 1 ||
		list.GetUsers()[0].GetId() != uid || leaks(list) {
		t.Fatalf("filtering: %v", list)
	}
	if list := must(h.users.ListUsers(h.root(), &keyorapb.ListUsersRequest{TenantId: tid, Status: "active"}))(t); list.GetTotal() != 0 {
		t.Fatalf("filtering: %v", list)
	}
	if list := must(h.sessions.ListSessions(h.root(), &keyorapb.ListSessionsRequest{TenantId: tid, UserId: uid, ActiveOnly: true}))(t); list.GetTotal() != 0 {
		t.Fatalf("disabled user still has active sessions: %v", list)
	}
	if list := must(h.sessions.ListSessions(h.root(), &keyorapb.ListSessionsRequest{TenantId: tid}))(t); list.GetTotal() != 1 || list.GetSessions()[0].GetRevokedAt() == nil {
		t.Fatalf("the revoked session should still be listed: %v", list)
	}

	// An administrator ends a session by ID.
	active := "active"
	must(h.users.UpdateUser(h.root(), &keyorapb.UpdateUserRequest{TenantId: tid, Id: uid, Status: &active}))(t)
	login = must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "bob@example.com", Password: password}))(t)
	must(h.sessions.RevokeSession(h.root(), &keyorapb.RevokeSessionRequest{TenantId: tid, Id: login.GetTokens().GetSessionId()}))(t)
	must(h.sessions.RevokeSession(h.root(), &keyorapb.RevokeSessionRequest{TenantId: tid, Id: login.GetTokens().GetSessionId()}))(t) // idempotent
	_, err = h.account.GetMe(h.bearer(login.GetTokens().GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.sessions.RevokeSession(h.root(), &keyorapb.RevokeSessionRequest{TenantId: tid, Id: "unknown"})
	expect(t, err, codes.NotFound, "not_found")

	// Permissions and roles.
	perm := must(h.roles.CreatePermission(h.root(), &keyorapb.CreatePermissionRequest{TenantId: tid, Name: "orders:read", Description: "Read orders"}))(t).GetPermission()
	if perm.GetId() == "" || perm.GetName() != "orders:read" || perm.GetDescription() != "Read orders" || perm.GetTenantId() != tid {
		t.Fatalf("permission: %v", perm)
	}
	for reason, req := range map[string]*keyorapb.CreatePermissionRequest{
		"name_taken":        {TenantId: tid, Name: "orders:read"},
		"validation_failed": {TenantId: tid, Name: "has spaces"},
	} {
		_, err = h.roles.CreatePermission(h.root(), req)
		if info := errorInfo(err); info.GetReason() != reason {
			t.Fatalf("got %v, want reason %s", err, reason)
		}
	}
	// The reserved prefix cannot be used, and control characters are refused.
	_, err = h.roles.CreatePermission(h.root(), &keyorapb.CreatePermissionRequest{TenantId: tid, Name: "keyora:super"})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	_, err = h.roles.CreatePermission(h.root(), &keyorapb.CreatePermissionRequest{TenantId: tid, Name: "ok:name", Description: "bad\x00byte"})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	if list := must(h.roles.ListPermissions(h.root(), &keyorapb.ListPermissionsRequest{TenantId: tid}))(t); list.GetTotal() != 2 {
		t.Fatalf("permissions (orders:read and the built-in keyora:admin): %v", list)
	}

	role := must(h.roles.CreateRole(h.root(), &keyorapb.CreateRoleRequest{TenantId: tid, Name: "viewer"}))(t).GetRole()
	rid := role.GetId()
	_, err = h.roles.CreateRole(h.root(), &keyorapb.CreateRoleRequest{TenantId: tid, Name: "viewer"})
	expect(t, err, codes.AlreadyExists, "name_taken")
	_, err = h.roles.SetRolePermissions(h.root(), &keyorapb.SetRolePermissionsRequest{TenantId: tid, Id: rid, Permissions: []string{"nope"}})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	if set := must(h.roles.SetRolePermissions(h.root(), &keyorapb.SetRolePermissionsRequest{TenantId: tid, Id: rid, Permissions: []string{"orders:read"}}))(t); strings.Join(set.GetRole().GetPermissions(), ",") != "orders:read" {
		t.Fatalf("role: %v", set)
	}
	newName, desc := "reader", "Read only"
	if upd := must(h.roles.UpdateRole(h.root(), &keyorapb.UpdateRoleRequest{TenantId: tid, Id: rid, Name: &newName, Description: &desc}))(t).GetRole(); upd.GetName() != "reader" || upd.GetDescription() != "Read only" {
		t.Fatalf("updated role: %v", upd)
	}
	if got := must(h.roles.GetRole(h.root(), &keyorapb.GetRoleRequest{TenantId: tid, Id: rid}))(t).GetRole(); got.GetName() != "reader" || len(got.GetPermissions()) != 1 {
		t.Fatalf("read role: %v", got)
	}
	if list := must(h.roles.ListRoles(h.root(), &keyorapb.ListRolesRequest{TenantId: tid}))(t); list.GetTotal() != 2 {
		t.Fatalf("roles (reader and the built-in keyora-admin): %v", list)
	}

	// The built-in role and permission are protected.
	adminRole := h.adminRole(tid)
	_, err = h.roles.DeleteRole(h.root(), &keyorapb.DeleteRoleRequest{TenantId: tid, Id: adminRole})
	expect(t, err, codes.PermissionDenied, "reserved")
	_, err = h.roles.SetRolePermissions(h.root(), &keyorapb.SetRolePermissionsRequest{TenantId: tid, Id: adminRole})
	expect(t, err, codes.PermissionDenied, "reserved")

	// Role assignment.
	assign := &keyorapb.AssignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: rid}
	must(h.users.AssignUserRole(h.root(), assign))(t)
	must(h.users.AssignUserRole(h.root(), assign))(t) // idempotent
	_, err = h.users.AssignUserRole(h.root(), &keyorapb.AssignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: "unknown"})
	expect(t, err, codes.NotFound, "not_found")
	if list := must(h.users.ListUserRoles(h.root(), &keyorapb.ListUserRolesRequest{TenantId: tid, UserId: uid}))(t); len(list.GetRoles()) != 1 || list.GetRoles()[0].GetName() != "reader" {
		t.Fatalf("user roles: %v", list)
	}
	must(h.users.UnassignUserRole(h.root(), &keyorapb.UnassignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: rid}))(t)
	if list := must(h.users.ListUserRoles(h.root(), &keyorapb.ListUserRolesRequest{TenantId: tid, UserId: uid}))(t); len(list.GetRoles()) != 0 {
		t.Fatalf("user roles after unassigning: %v", list)
	}

	// Deleting a permission takes it off the roles that granted it.
	must(h.roles.DeletePermission(h.root(), &keyorapb.DeletePermissionRequest{TenantId: tid, Id: perm.GetId()}))(t)
	if got := must(h.roles.GetRole(h.root(), &keyorapb.GetRoleRequest{TenantId: tid, Id: rid}))(t).GetRole(); len(got.GetPermissions()) != 0 {
		t.Fatalf("deleted permission still on role: %v", got)
	}
	must(h.roles.DeleteRole(h.root(), &keyorapb.DeleteRoleRequest{TenantId: tid, Id: rid}))(t)
	_, err = h.roles.GetRole(h.root(), &keyorapb.GetRoleRequest{TenantId: tid, Id: rid})
	expect(t, err, codes.NotFound, "not_found")

	must(h.users.DeleteUser(h.root(), &keyorapb.DeleteUserRequest{TenantId: tid, Id: uid}))(t)
	_, err = h.users.GetUser(h.root(), &keyorapb.GetUserRequest{TenantId: tid, Id: uid})
	expect(t, err, codes.NotFound, "not_found")

	// Every change above is in the audit trail, with its actor.
	events := must(h.audit.ListAuditEvents(h.root(), &keyorapb.ListAuditEventsRequest{TenantId: tid, Type: "user.deleted", ActorId: "admin-key"}))(t)
	if events.GetTotal() != 1 || events.GetEvents()[0].GetTargetId() != uid || events.GetEvents()[0].GetActorType() != "root" ||
		events.GetEvents()[0].GetRequestId() == "" || events.GetEvents()[0].GetCreatedAt() == nil {
		t.Fatalf("audit trail: %v", events)
	}
	if none := must(h.audit.ListAuditEvents(h.root(), &keyorapb.ListAuditEventsRequest{TenantId: tid, Type: "user.deleted", ActorId: "someone-else"}))(t); none.GetTotal() != 0 {
		t.Fatalf("actor filter: %v", none)
	}
}
