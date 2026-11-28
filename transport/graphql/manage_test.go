package graphqlapi_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestManagementRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	root := func(query string, vars M) result {
		t.Helper()
		if vars == nil {
			vars = M{}
		}
		vars["t"] = tid
		return h.gql(adminKey, query, vars)
	}

	// ---- tenants ----
	h.fails(h.gql(adminKey, `mutation { createTenant(slug: "acme", name: "Again") { id } }`, nil), "slug_taken")
	got := h.ok(root(`query($t: ID!) { tenant(id: $t) { id slug name status createdAt updatedAt } }`, nil))
	if got.str("tenant.slug") != "acme" || got.str("tenant.status") != "active" || got.str("tenant.createdAt") == "" {
		t.Fatalf("tenant: %s", got.Raw)
	}
	h.fails(h.gql(adminKey, `{ tenant(id: "unknown") { id } }`, nil), "not_found")
	renamed := h.ok(root(`mutation($t: ID!) { updateTenant(id: $t, name: "Acme Inc.") { name status } }`, nil))
	if renamed.str("updateTenant.name") != "Acme Inc." || renamed.str("updateTenant.status") != "active" {
		t.Fatalf("updateTenant: %s", renamed.Raw)
	}
	h.tenant("beta")
	all := h.ok(h.gql(adminKey, `{ tenants(limit: 1, offset: 1) { items { slug } total limit offset } }`, nil))
	if all.num("tenants.total") != 2 || all.num("tenants.limit") != 1 || all.num("tenants.offset") != 1 || len(all.at("tenants.items").([]any)) != 1 {
		t.Fatalf("tenants: %s", all.Raw)
	}

	// ---- applications ----
	const appFields = `id tenantId name type clientId redirectUris allowedOrigins accessTokenTtlSeconds refreshTokenTtlSeconds status createdAt updatedAt`
	app := h.ok(root(`mutation($t: ID!) {
		createApplication(tenantId: $t, input: {
			name: "api", redirectUris: ["https://api.test/cb"], accessTokenTtlSeconds: 300
		}) { application { `+appFields+` } clientSecret }
	}`, nil))
	appID, cid, oldSecret := app.str("createApplication.application.id"), app.str("createApplication.application.clientId"), app.str("createApplication.clientSecret")
	if app.str("createApplication.application.type") != "confidential" ||
		app.num("createApplication.application.accessTokenTtlSeconds") != 300 || app.str("createApplication.application.redirectUris.0") != "https://api.test/cb" ||
		len(app.at("createApplication.application.allowedOrigins").([]any)) != 0 || !strings.HasPrefix(oldSecret, "kys_") {
		t.Fatalf("createApplication: %s", app.Raw)
	}
	one := h.ok(root(`query($t: ID!, $id: ID!) { application(tenantId: $t, id: $id) { `+appFields+` } }`, M{"id": appID}))
	if one.str("application.clientId") != cid || strings.Contains(one.Raw, oldSecret) {
		t.Fatalf("application: %s", one.Raw)
	}
	list := h.ok(root(`query($t: ID!) { applications(tenantId: $t, limit: 1, offset: 1) { items { `+appFields+` } total limit offset } }`, nil))
	if list.num("applications.total") != 2 || list.num("applications.limit") != 1 || list.num("applications.offset") != 1 || len(list.at("applications.items").([]any)) != 1 {
		t.Fatalf("applications: %s", list.Raw)
	}
	h.fails(root(`mutation($t: ID!) { createApplication(tenantId: $t, input: {name: "api"}) { clientSecret } }`, nil), "name_taken")
	h.fails(root(`mutation($t: ID!) { createApplication(tenantId: $t, input: {}) { clientSecret } }`, nil), "validation_failed")
	upd := h.ok(root(`mutation($t: ID!, $id: ID!) {
		updateApplication(tenantId: $t, id: $id, input: {name: "api v2", allowedOrigins: ["https://api.test"]}) { name allowedOrigins redirectUris accessTokenTtlSeconds }
	}`, M{"id": appID}))
	if upd.str("updateApplication.name") != "api v2" || upd.str("updateApplication.allowedOrigins.0") != "https://api.test" ||
		upd.str("updateApplication.redirectUris.0") != "https://api.test/cb" || upd.num("updateApplication.accessTokenTtlSeconds") != 300 {
		t.Fatalf("updateApplication changed omitted fields or missed given ones: %s", upd.Raw)
	}
	bad := h.fails(root(`mutation($t: ID!, $id: ID!) { updateApplication(tenantId: $t, id: $id, input: {accessTokenTtlSeconds: 5}) { id } }`, M{"id": appID}), "validation_failed")
	if bad.Errors[0].Extensions.Details["access_token_ttl_seconds"] == "" {
		t.Fatalf("validation error does not name the field: %s", bad.Raw)
	}
	rot := h.ok(root(`mutation($t: ID!, $id: ID!) { rotateApplicationSecret(tenantId: $t, id: $id) { application { id } clientSecret } }`, M{"id": appID}))
	newSecret := rot.str("rotateApplicationSecret.clientSecret")
	if newSecret == oldSecret || rot.str("rotateApplicationSecret.application.id") != appID {
		t.Fatalf("rotateApplicationSecret: %s", rot.Raw)
	}
	h.fails(h.gql(cid+":"+oldSecret, loginMutation, M{"email": "a@b.co", "password": password}), "invalid_client")
	h.fails(h.gql(cid+":"+newSecret, loginMutation, M{"email": "a@b.co", "password": password}), "invalid_credentials")
	const deleteApp = `mutation($t: ID!, $id: ID!) { deleteApplication(tenantId: $t, id: $id) }`
	if r := h.ok(root(deleteApp, M{"id": appID})); r.at("deleteApplication") != true {
		t.Fatalf("deleteApplication: %s", r.Raw)
	}
	h.fails(root(deleteApp, M{"id": appID}), "not_found")

	// ---- users ----
	const userFields = `id tenantId email name status emailVerified lockedUntil lastLoginAt createdAt updatedAt`
	u := h.ok(root(`mutation($t: ID!) {
		createUser(tenantId: $t, email: "Bob@Example.com", password: "`+password+`", name: "Bob", emailVerified: true) { `+userFields+` }
	}`, nil))
	uid := u.str("createUser.id")
	if u.str("createUser.email") != "bob@example.com" || u.at("createUser.emailVerified") != true || u.at("createUser.lastLoginAt") != nil {
		t.Fatalf("createUser: %s", u.Raw)
	}
	h.fails(root(`mutation($t: ID!) { createUser(tenantId: $t, email: "bob@example.com", password: "`+password+`") { id } }`, nil), "email_taken")
	login := h.ok(h.gql(client, loginMutation, M{"email": "bob@example.com", "password": password}))
	seen := h.ok(root(`query($t: ID!, $id: ID!) { user(tenantId: $t, id: $id) { `+userFields+` } }`, M{"id": uid}))
	if seen.at("user.lastLoginAt") == nil {
		t.Fatalf("user after sign-in: %s", seen.Raw)
	}
	disabled := h.ok(root(`mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, status: "disabled") { status name } }`, M{"id": uid}))
	if disabled.str("updateUser.status") != "disabled" || disabled.str("updateUser.name") != "Bob" {
		t.Fatalf("updateUser: %s", disabled.Raw)
	}
	h.fails(h.gql(login.str("login.tokens.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")
	if r := h.ok(root(`query($t: ID!) { users(tenantId: $t, status: "disabled", email: "BOB") { items { `+userFields+` } total } }`, nil)); r.num("users.total") != 1 || r.str("users.items.0.id") != uid {
		t.Fatalf("filtering: %s", r.Raw)
	}
	if r := h.ok(root(`query($t: ID!) { users(tenantId: $t, status: "active") { total } }`, nil)); r.num("users.total") != 0 {
		t.Fatalf("filtering: %s", r.Raw)
	}
	if r := h.ok(root(`query($t: ID!, $u: ID) { sessions(tenantId: $t, userId: $u, active: true) { total } }`, M{"u": uid})); r.num("sessions.total") != 0 {
		t.Fatalf("disabled user still has active sessions: %s", r.Raw)
	}
	if r := h.ok(root(`query($t: ID!, $u: ID) { sessions(tenantId: $t, userId: $u) { items { id userId applicationId revokedAt } total } }`, M{"u": uid})); r.num("sessions.total") != 1 || r.at("sessions.items.0.revokedAt") == nil {
		t.Fatalf("sessions: %s", r.Raw)
	}
	h.ok(root(`mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, status: "active") { id } }`, M{"id": uid}))

	// Lockout and unlock.
	for i := 0; i < 3; i++ {
		h.fails(h.gql(client, loginMutation, M{"email": "bob@example.com", "password": "guess " + string(rune('a'+i))}), "invalid_credentials")
	}
	h.fails(h.gql(client, loginMutation, M{"email": "bob@example.com", "password": password}), "account_locked")
	if r := h.ok(root(`mutation($t: ID!, $id: ID!) { unlockUser(tenantId: $t, id: $id) { lockedUntil } }`, M{"id": uid})); r.at("unlockUser.lockedUntil") != nil {
		t.Fatalf("unlockUser: %s", r.Raw)
	}
	session := h.ok(h.gql(client, loginMutation, M{"email": "bob@example.com", "password": password}))

	// ---- sessions ----
	h.ok(root(`mutation($t: ID!, $id: ID!) { revokeSession(tenantId: $t, id: $id) }`, M{"id": session.str("login.tokens.sessionId")}))
	h.fails(h.gql(session.str("login.tokens.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")
	h.fails(root(`mutation($t: ID!) { revokeSession(tenantId: $t, id: "unknown") }`, nil), "not_found")

	// ---- permissions and roles ----
	perm := h.ok(root(`mutation($t: ID!) { createPermission(tenantId: $t, name: "orders:read") { id tenantId name description createdAt } }`, nil))
	if perm.str("createPermission.name") != "orders:read" || perm.str("createPermission.description") != "" {
		t.Fatalf("createPermission: %s", perm.Raw)
	}
	h.fails(root(`mutation($t: ID!) { createPermission(tenantId: $t, name: "orders:read") { id } }`, nil), "name_taken")
	h.fails(root(`mutation($t: ID!) { createPermission(tenantId: $t, name: "has spaces") { id } }`, nil), "validation_failed")
	// The reserved permission namespace cannot be minted.
	h.fails(root(`mutation($t: ID!) { createPermission(tenantId: $t, name: "keyora:super") { id } }`, nil), "validation_failed")
	if r := h.ok(root(`query($t: ID!) { permissions(tenantId: $t) { items { name } total } }`, nil)); r.num("permissions.total") != 2 {
		t.Fatalf("permissions: %s", r.Raw)
	}

	const roleFields = `id tenantId name description permissions createdAt updatedAt`
	role := h.ok(root(`mutation($t: ID!) { createRole(tenantId: $t, name: "viewer") { `+roleFields+` } }`, nil))
	rid := role.str("createRole.id")
	const setPerms = `mutation($t: ID!, $id: ID!, $p: [String!]!) { setRolePermissions(tenantId: $t, id: $id, permissions: $p) { permissions } }`
	h.fails(root(setPerms, M{"id": rid, "p": []string{"nope"}}), "validation_failed")
	if r := h.ok(root(setPerms, M{"id": rid, "p": []string{"orders:read"}})); r.str("setRolePermissions.permissions.0") != "orders:read" {
		t.Fatalf("setRolePermissions: %s", r.Raw)
	}
	if r := h.ok(root(`mutation($t: ID!, $id: ID!) { updateRole(tenantId: $t, id: $id, name: "reader", description: "Read only") { name description permissions } }`, M{"id": rid})); r.str("updateRole.name") != "reader" || r.str("updateRole.description") != "Read only" || r.str("updateRole.permissions.0") != "orders:read" {
		t.Fatalf("updateRole: %s", r.Raw)
	}
	const assign = `mutation($t: ID!, $u: ID!, $r: ID!) { assignRole(tenantId: $t, userId: $u, roleId: $r) }`
	h.ok(root(assign, M{"u": uid, "r": rid}))
	h.ok(root(assign, M{"u": uid, "r": rid})) // idempotent
	h.fails(root(assign, M{"u": uid, "r": "unknown"}), "not_found")
	const userRoles = `query($t: ID!, $u: ID!) { userRoles(tenantId: $t, userId: $u) { ` + roleFields + ` } }`
	if r := h.ok(root(userRoles, M{"u": uid})); len(r.at("userRoles").([]any)) != 1 || r.str("userRoles.0.name") != "reader" {
		t.Fatalf("userRoles: %s", r.Raw)
	}
	h.ok(root(`mutation($t: ID!, $u: ID!, $r: ID!) { unassignRole(tenantId: $t, userId: $u, roleId: $r) }`, M{"u": uid, "r": rid}))
	if r := h.ok(root(userRoles, M{"u": uid})); len(r.at("userRoles").([]any)) != 0 {
		t.Fatalf("userRoles after unassign: %s", r.Raw)
	}
	h.ok(root(`mutation($t: ID!, $id: ID!) { deletePermission(tenantId: $t, id: $id) }`, M{"id": perm.str("createPermission.id")}))
	if r := h.ok(root(`query($t: ID!, $id: ID!) { role(tenantId: $t, id: $id) { permissions } }`, M{"id": rid})); len(r.at("role.permissions").([]any)) != 0 {
		t.Fatalf("deleted permission still on role: %s", r.Raw)
	}
	if r := h.ok(root(`query($t: ID!) { roles(tenantId: $t) { items { name } total } }`, nil)); r.num("roles.total") != 2 {
		t.Fatalf("roles: %s", r.Raw)
	}
	h.ok(root(`mutation($t: ID!, $id: ID!) { deleteRole(tenantId: $t, id: $id) }`, M{"id": rid}))
	h.ok(root(`mutation($t: ID!, $id: ID!) { deleteUser(tenantId: $t, id: $id) }`, M{"id": uid}))
	h.fails(root(`query($t: ID!, $id: ID!) { user(tenantId: $t, id: $id) { id } }`, M{"id": uid}), "not_found")

	// ---- audit ----
	events := h.ok(root(`query($t: ID!) { auditEvents(tenantId: $t, actorId: "admin-key", limit: 100) { items { type actorType actorId targetId ip userAgent requestId metadata createdAt } total } }`, nil))
	if events.num("auditEvents.total") < 10 || events.str("auditEvents.items.0.actorType") != "root" {
		t.Fatalf("audit events: %s", events.Raw)
	}
	if r := h.ok(root(`query($t: ID!) { auditEvents(tenantId: $t, type: "user.deleted") { items { targetId metadata } total } }`, nil)); r.num("auditEvents.total") != 1 || r.str("auditEvents.items.0.targetId") != uid {
		t.Fatalf("audit filter: %s", r.Raw)
	}
	if _, isObject := events.at("auditEvents.items.0.metadata").(map[string]any); !isObject {
		t.Fatalf("metadata is not a JSON object: %s", events.Raw)
	}

	// Suspending the tenant rejects its applications at once.
	h.ok(root(`mutation($t: ID!) { updateTenant(id: $t, status: "suspended") { status } }`, nil))
	h.fails(h.gql(client, loginMutation, M{"email": "bob@example.com", "password": password}), "invalid_client")
}

func TestPaginationArguments(t *testing.T) {
	h := newHarness(t, nil)
	for query, field := range map[string]string{
		`{ tenants(limit: 0) { total } }`:               "limit",
		`{ tenants(limit: 101) { total } }`:             "limit",
		`{ tenants(limit: -5) { total } }`:              "limit",
		`{ tenants(offset: -1) { total } }`:             "offset",
		`{ tenants(limit: 100, offset: -1) { total } }`: "offset",
	} {
		r := h.fails(h.gql(adminKey, query, nil), "validation_failed")
		if r.Errors[0].Extensions.Details[field] == "" {
			t.Errorf("%s: details do not name %q: %s", query, field, r.Raw)
		}
	}
	// null means "use the default", exactly like leaving the argument out.
	r := h.ok(h.gql(adminKey, `query($l: Int, $o: Int) { tenants(limit: $l, offset: $o) { limit offset } }`, M{"l": nil, "o": nil}))
	if r.num("tenants.limit") != 20 || r.num("tenants.offset") != 0 {
		t.Fatalf("defaults: %s", r.Raw)
	}
	h.ok(h.gql(adminKey, `{ tenants(limit: 100) { limit } }`, nil))
	// A limit that is not a 32-bit integer never reaches a resolver.
	if r := h.gql(adminKey, `{ tenants(limit: 99999999999) { total } }`, nil); len(r.Errors) == 0 || r.at("tenants") != nil {
		t.Fatalf("oversized limit: %s", r.Raw)
	}
}

// An origin added through GraphQL is honoured by the CORS check at once,
// exactly as one added through REST.
func TestOriginChangeAppliesImmediately(t *testing.T) {
	h := newHarness(t, nil)
	tenantID, _ := h.tenant("cors")
	preflight := func() string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodOptions, h.srv.URL+"/graphql", nil)
		req.Header.Set("Origin", "https://spa.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.Header.Get("Access-Control-Allow-Origin")
	}
	if got := preflight(); got != "" {
		t.Fatalf("origin allowed before it was registered: %q", got)
	}
	h.ok(h.gql(adminKey, `mutation($t: ID!) { createApplication(tenantId: $t, input: {name: "spa", type: "public", allowedOrigins: ["https://spa.example.com"]}) { application { id } } }`, M{"t": tenantID}))
	if got := preflight(); got != "https://spa.example.com" {
		t.Fatalf("origin registered through GraphQL not honoured at once: %q", got)
	}
}
