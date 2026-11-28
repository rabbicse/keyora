package graphqlapi_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	graphql "github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/ast"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	graphqlapi "github.com/rabbicse/keyora/transport/graphql"
)

// managementFields is one use of every management field, with $t the tenant
// and $id any other ID. rootOnly marks the fields a tenant administrator may
// not use even for their own tenant.
var managementFields = []struct {
	query    string
	rootOnly bool
}{
	{query: `query($t: ID!) { tenant(id: $t) { id } }`},
	{query: `query($t: ID!) { applications(tenantId: $t) { total } }`},
	{query: `query($t: ID!, $id: ID!) { application(tenantId: $t, id: $id) { id } }`},
	{query: `query($t: ID!) { users(tenantId: $t) { total } }`},
	{query: `query($t: ID!, $id: ID!) { user(tenantId: $t, id: $id) { id } }`},
	{query: `query($t: ID!, $id: ID!) { userRoles(tenantId: $t, userId: $id) { id } }`},
	{query: `query($t: ID!) { permissions(tenantId: $t) { total } }`},
	{query: `query($t: ID!) { roles(tenantId: $t) { total } }`},
	{query: `query($t: ID!, $id: ID!) { role(tenantId: $t, id: $id) { id } }`},
	{query: `query($t: ID!) { sessions(tenantId: $t) { total } }`},
	{query: `query($t: ID!) { auditEvents(tenantId: $t) { total } }`},
	{query: `mutation($t: ID!) { createApplication(tenantId: $t, input: {name: "evil"}) { clientSecret } }`},
	{query: `mutation($t: ID!, $id: ID!) { updateApplication(tenantId: $t, id: $id, input: {name: "y"}) { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { deleteApplication(tenantId: $t, id: $id) }`},
	{query: `mutation($t: ID!, $id: ID!) { rotateApplicationSecret(tenantId: $t, id: $id) { clientSecret } }`},
	{query: `mutation($t: ID!) { createUser(tenantId: $t, email: "plant@example.com", password: "` + password + `") { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, status: "disabled") { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { deleteUser(tenantId: $t, id: $id) }`},
	{query: `mutation($t: ID!, $id: ID!) { unlockUser(tenantId: $t, id: $id) { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { assignRole(tenantId: $t, userId: $id, roleId: $id) }`},
	{query: `mutation($t: ID!, $id: ID!) { unassignRole(tenantId: $t, userId: $id, roleId: $id) }`},
	{query: `mutation($t: ID!) { createPermission(tenantId: $t, name: "x:y") { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { deletePermission(tenantId: $t, id: $id) }`},
	{query: `mutation($t: ID!) { createRole(tenantId: $t, name: "god", permissions: ["keyora:admin"]) { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { updateRole(tenantId: $t, id: $id, description: "x") { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { deleteRole(tenantId: $t, id: $id) }`},
	{query: `mutation($t: ID!, $id: ID!) { setRolePermissions(tenantId: $t, id: $id, permissions: []) { id } }`},
	{query: `mutation($t: ID!, $id: ID!) { revokeSession(tenantId: $t, id: $id) }`},
	{query: `{ tenants { total } }`, rootOnly: true},
	{query: `mutation { createTenant(slug: "mine", name: "Mine") { id } }`, rootOnly: true},
	{query: `mutation($t: ID!) { updateTenant(id: $t, status: "suspended") { id } }`, rootOnly: true},
}

// vars gives a document only the variables it declares.
func vars(query, tenantID, id string) M {
	v := M{}
	if strings.Contains(query, "$t:") {
		v["t"] = tenantID
	}
	if strings.Contains(query, "$id:") {
		v["id"] = id
	}
	return v
}

// The schema's management fields and the list above must not drift apart: a
// new field without an entry would escape the privilege tests.
func TestEveryManagementFieldIsCovered(t *testing.T) {
	schema := graphql.MustParseSchema(graphqlapi.Schema, nil, graphql.UseStringDescriptions())
	open := map[string]bool{ // fields that are not management fields
		"introspectToken": true, "userinfo": true, "me": true, "mySessions": true,
		"register": true, "login": true, "refresh": true, "logout": true, "requestEmailVerification": true, "confirmEmail": true,
		"forgotPassword": true, "resetPassword": true, "authorize": true, "token": true,
		"updateMe": true, "changePassword": true, "revokeMySession": true,
	}
	for _, root := range []string{"Query", "Mutation"} {
		for _, f := range schema.AST().Types[root].(*ast.ObjectTypeDefinition).Fields {
			if open[f.Name] {
				continue
			}
			covered := false
			for _, m := range managementFields {
				covered = covered || strings.Contains(m.query, " "+f.Name+"(") || strings.Contains(m.query, " "+f.Name+" ")
			}
			if !covered {
				t.Errorf("%s.%s is not in managementFields", root, f.Name)
			}
		}
	}
}

func TestPrivilegeEscalation(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	uid, access, _ := h.user(client, "mallory@example.com")
	adminRole := h.adminRole(tid)

	// An ordinary user is refused by every management field of their own
	// tenant; so is a caller without a valid credential.
	for _, f := range managementFields {
		for who, c := range map[string]struct{ token, want string }{
			"user":                 {access, "forbidden"},
			"anonymous":            {"", "unauthenticated"},
			"garbage":              {"not-a-token", "invalid_token"},
			"almost the admin key": {adminKey + "x", "invalid_token"},
		} {
			id := uid
			if strings.Contains(f.query, "roleId: $id") || strings.Contains(f.query, "Role(") {
				id = adminRole // self-promotion, or tampering with the admin role
			}
			r := h.gql(c.token, f.query, vars(f.query, tid, id))
			if len(r.Errors) != 1 || r.Errors[0].Extensions.Code != c.want || strings.Contains(r.Raw, "kys_") {
				t.Errorf("%s as %s: got %s, want %s", f.query, who, r.Raw, c.want)
			}
		}
	}

	// Self-service and registration have no arguments for privileged fields.
	for _, q := range []string{
		`mutation { updateMe(name: "M", status: "active") { id } }`,
		`mutation { updateMe(name: "M", emailVerified: true) { id } }`,
		`mutation { updateMe(name: "M", roles: ["keyora-admin"]) { id } }`,
		`mutation { register(email: "z@example.com", password: "` + password + `", roles: ["keyora-admin"]) { id } }`,
	} {
		token := access
		if strings.Contains(q, "register") {
			token = client
		}
		if r := h.gql(token, q, nil); len(r.Errors) == 0 || r.Errors[0].Extensions.Code != "invalid_query" || r.Data != nil {
			t.Errorf("%s: got %s, want invalid_query", q, r.Raw)
		}
	}
	// Neither do the management fields for what REST refuses to change.
	for _, q := range []string{
		`mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, password: "sneaky new password") { id } }`,
		`mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, email: "other@example.com") { id } }`,
		`mutation($t: ID!) { updateTenant(id: $t, slug: "other") { id } }`,
	} {
		if r := h.gql(adminKey, q, vars(q, tid, uid)); len(r.Errors) == 0 || r.Errors[0].Extensions.Code != "invalid_query" || r.Data != nil {
			t.Errorf("%s: got %s, want invalid_query", q, r.Raw)
		}
	}
	me := h.ok(h.gql(access, `{ me { user { emailVerified name } roles permissions } }`, nil))
	if len(me.at("me.roles").([]any)) != 0 || len(me.at("me.permissions").([]any)) != 0 || me.at("me.user.emailVerified") != false || me.str("me.user.name") != "Ada" {
		t.Fatalf("user gained privileges: %s", me.Raw)
	}

	// Once promoted by root, the same token works at once (roles are read
	// live), for the tenant but not for root-only fields, and stops working
	// the moment the role is taken away.
	h.makeAdmin(tid, uid)
	for _, f := range managementFields {
		if !f.rootOnly {
			continue
		}
		h.fails(h.gql(access, f.query, vars(f.query, tid, uid)), "forbidden")
	}
	h.ok(h.gql(access, `query($t: ID!) { users(tenantId: $t) { total } tenant(id: $t) { slug } }`, M{"t": tid}))
	h.ok(h.gql(adminKey, `mutation($t: ID!, $u: ID!, $r: ID!) { unassignRole(tenantId: $t, userId: $u, roleId: $r) }`, M{"t": tid, "u": uid, "r": adminRole}))
	h.fails(h.gql(access, `query($t: ID!) { users(tenantId: $t) { total } }`, M{"t": tid}), "forbidden")
}

func TestRootAccessDisabledWithoutAdminKey(t *testing.T) {
	h := newHarness(t, func(s *setup) { s.API.AdminKey = "" })
	h.fails(h.gql("", `{ tenants { total } }`, nil), "unauthenticated")
	h.fails(h.gql(adminKey, `{ tenants { total } }`, nil), "invalid_token")
}

func TestCrossTenantAccessIsDenied(t *testing.T) {
	h := newHarness(t, nil)
	tidA, clientA := h.tenant("acme")
	tidB, clientB := h.tenant("beta")
	adminA, accessA, refreshA := h.user(clientA, "admin@example.com")
	h.makeAdmin(tidA, adminA)
	victim, victimAccess, _ := h.user(clientB, "victim@example.com")

	b := h.ok(h.gql(adminKey, `query($t: ID!) {
		applications(tenantId: $t) { items { id } }
		sessions(tenantId: $t) { items { id } }
		roles(tenantId: $t) { items { id } }
	}`, M{"t": tidB}))
	appB, sessionB, roleB := b.str("applications.items.0.id"), b.str("sessions.items.0.id"), b.str("roles.items.0.id")
	// The ID each field is aimed at in tenant B.
	target := func(query string) string {
		switch {
		case strings.Contains(query, "pplication"):
			return appB
		case strings.Contains(query, "ession"):
			return sessionB
		case strings.Contains(query, "ole") && !strings.Contains(query, "userId"):
			return roleB
		}
		return victim
	}

	// Sanity: A's administrator works in A.
	h.ok(h.gql(accessA, `query($t: ID!) { users(tenantId: $t) { total } }`, M{"t": tidA}))

	// Tenant B named in tenantId: every management field is refused outright.
	for _, f := range managementFields {
		if f.rootOnly {
			continue
		}
		r := h.gql(accessA, f.query, vars(f.query, tidB, target(f.query)))
		if len(r.Errors) != 1 || r.Errors[0].Extensions.Code != "forbidden" || strings.Contains(r.Raw, "kys_") {
			t.Errorf("%s against tenant B: got %s, want forbidden", f.query, r.Raw)
		}
	}
	// One document cannot mix an allowed tenant with a foreign one.
	mixed := h.gql(accessA, `query($a: ID!, $b: ID!) { mine: users(tenantId: $a) { total } theirs: users(tenantId: $b) { total items { email } } }`, M{"a": tidA, "b": tidB})
	if mixed.at("mine.total") == nil || mixed.at("theirs") != nil || mixed.codeAt("theirs") != "forbidden" || strings.Contains(mixed.Raw, "victim@example.com") {
		t.Fatalf("mixed tenants: %s", mixed.Raw)
	}

	// Own tenant in tenantId, tenant B's IDs in the rest: not found.
	for _, q := range []string{
		`query($t: ID!, $id: ID!) { user(tenantId: $t, id: $id) { id } }`,
		`mutation($t: ID!, $id: ID!) { updateUser(tenantId: $t, id: $id, status: "disabled") { id } }`,
		`mutation($t: ID!, $id: ID!) { deleteUser(tenantId: $t, id: $id) }`,
		`mutation($t: ID!, $id: ID!) { unlockUser(tenantId: $t, id: $id) { id } }`,
		`query($t: ID!, $id: ID!) { userRoles(tenantId: $t, userId: $id) { id } }`,
		`query($t: ID!, $id: ID!) { application(tenantId: $t, id: $id) { id } }`,
		`mutation($t: ID!, $id: ID!) { deleteApplication(tenantId: $t, id: $id) }`,
		`mutation($t: ID!, $id: ID!) { rotateApplicationSecret(tenantId: $t, id: $id) { clientSecret } }`,
		`mutation($t: ID!, $id: ID!) { revokeSession(tenantId: $t, id: $id) }`,
		`query($t: ID!, $id: ID!) { role(tenantId: $t, id: $id) { id } }`,
		`mutation($id: ID!) { revokeMySession(sessionId: $id) }`,
	} {
		r := h.gql(accessA, q, vars(q, tidA, target(q)))
		if len(r.Errors) != 1 || r.Errors[0].Extensions.Code != "not_found" || strings.Contains(r.Raw, "kys_") {
			t.Errorf("%s with tenant B's ID: got %s, want not_found", q, r.Raw)
		}
	}
	// A's admin role cannot be granted to B's user.
	h.fails(h.gql(accessA, `mutation($t: ID!, $u: ID!, $r: ID!) { assignRole(tenantId: $t, userId: $u, roleId: $r) }`,
		M{"t": tidA, "u": victim, "r": h.adminRole(tidA)}), "not_found")

	// Tokens do not cross tenants through the authentication fields either.
	h.fails(h.gql(clientB, `mutation($rt: String!) { refresh(refreshToken: $rt) { accessToken } }`, M{"rt": refreshA}), "invalid_refresh_token")
	in := h.ok(h.gql(clientB, `query($token: String!) { introspectToken(token: $token) { active subject email } }`, M{"token": accessA}))
	if in.at("introspectToken.active") != false || strings.Contains(in.Raw, adminA) {
		t.Fatalf("tenant B introspected tenant A's token: %s", in.Raw)
	}
	h.fails(h.gql(clientB, loginMutation, M{"email": "admin@example.com", "password": password}), "invalid_credentials")

	// Nothing above harmed the victim or tenant B.
	h.ok(h.gql(victimAccess, `{ me { user { id } } }`, nil))
	after := h.ok(h.gql(adminKey, `query($t: ID!) { users(tenantId: $t) { total } applications(tenantId: $t) { total } roles(tenantId: $t) { total } permissions(tenantId: $t) { total } }`, M{"t": tidB}))
	if after.num("users.total") != 1 || after.num("applications.total") != 1 || after.num("roles.total") != 1 || after.num("permissions.total") != 1 {
		t.Fatalf("tenant B changed: %s", after.Raw)
	}
}

// fixedLimiter never refills, so a test sees exactly its burst.
func fixedLimiter(burst int) *ratelimit.Limiter {
	l := ratelimit.New(60, burst)
	now := time.Now()
	l.SetClock(func() time.Time { return now })
	return l
}

// One HTTP request may carry hundreds of aliased login fields. Each one must
// spend the caller's rate-limit budget, or a single request would be an
// unlimited password-guessing oracle.
func TestAliasedLoginsAreThrottledPerField(t *testing.T) {
	const burst, attempts = 5, 200
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	h.user(client, "ada@example.com")
	h.ok(h.gql(adminKey, `mutation($t: ID!) { createUser(tenantId: $t, email: "bob@example.com", password: "`+password+`") { id } }`, M{"t": tid}))

	// Each round runs against a fresh server on the same data, with a rate
	// limiter of its own.
	guess := func(email string, pw func(i int) string) (*harness, result) {
		h2 := &harness{t: t, env: h.env, logs: h.logs}
		h2.srv = h2.serve(func(s *setup) { s.API.Limiter = fixedLimiter(burst) })
		// Written tightly, as an attacker would, to fit the most guesses
		// into the document size limit.
		var doc strings.Builder
		doc.WriteString("mutation($e:String!){")
		for i := 0; i < attempts; i++ {
			fmt.Fprintf(&doc, "a%d:login(email:$e,password:%q){tokens{accessToken}}", i, pw(i))
		}
		doc.WriteString("}")
		if doc.Len() > graphqlapi.MaxQueryBytes {
			t.Fatalf("the test document is %d bytes; it must fit the limit to test the throttle", doc.Len())
		}
		return h2, h2.gql(client, doc.String(), M{"e": email})
	}
	count := func(r result) map[string]int {
		got := map[string]int{}
		for i := 0; i < attempts; i++ {
			alias := fmt.Sprintf("a%d", i)
			code := r.codeAt(alias)
			if code == "" && r.at(alias+".tokens.accessToken") != nil {
				code = "signed in"
			}
			got[code]++
		}
		return got
	}

	// Password guessing: only the first few guesses are even looked at.
	_, r := guess("bob@example.com", func(i int) string { return fmt.Sprintf("guess number %d", i) })
	if got := count(r); r.Status != 200 || got["rate_limited"] != attempts-burst || got["invalid_credentials"]+got["account_locked"] != burst || len(got) > 3 {
		t.Fatalf("%d aliased guesses with a burst of %d: %v", attempts, burst, got)
	}
	if e := r.Errors[len(r.Errors)-1]; e.Extensions.Code != "rate_limited" || e.Extensions.Details["retry_after_seconds"] == "" {
		t.Fatalf("rate limit error: %+v", e)
	}

	// The same holds when the credentials are right: the limit is on the
	// operation, not on failures.
	h2, r := guess("ada@example.com", func(int) string { return password })
	if got := count(r); got["signed in"] != burst || got["rate_limited"] != attempts-burst {
		t.Fatalf("%d aliased sign-ins with a burst of %d: %v", attempts, burst, got)
	}
	// The budget is shared with the REST API and with later requests.
	h2.fails(h2.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}), "rate_limited")
	if status := h2.restLogin(client, "ada@example.com", password); status != 429 {
		t.Fatalf("REST login after the GraphQL burst: %d, want 429", status)
	}
	// Fields that take no credentials are not limited.
	h2.ok(h2.gql(adminKey, `{ tenants { total } }`, nil))
}

// Every field that REST serves under /api/v1/auth/ or /api/v1/oauth/ is
// rate limited, and the limit is checked before anything else: before the
// application or the user is identified, and before arguments are looked at.
func TestEveryCredentialFieldIsThrottled(t *testing.T) {
	fields := []string{
		`mutation { register(email: "a@example.com", password: "` + password + `") { id } }`,
		`mutation { login(email: "a@example.com", password: "` + password + `") { tokens { accessToken } } }`,
		`mutation { refresh(refreshToken: "x") { accessToken } }`,
		`mutation { logout }`,
		`mutation { logout(refreshToken: "x") }`,
		`{ introspectToken(token: "x") { active } }`,
		`mutation { requestEmailVerification(email: "a@example.com") }`,
		`mutation { confirmEmail(token: "x") }`,
		`mutation { forgotPassword(email: "a@example.com") }`,
		`mutation { resetPassword(token: "x", newPassword: "y") }`,
		`mutation { authorize(input: {clientId: "x", redirectUri: "y", codeChallenge: "z", codeChallengeMethod: "S256", email: "a@example.com", password: "p"}) { code } }`,
		`mutation { token(input: {grantType: AUTHORIZATION_CODE}) { accessToken } }`,
		`mutation { token(input: {grantType: REFRESH_TOKEN}) { accessToken } }`,
		`mutation { token(input: {grantType: CLIENT_CREDENTIALS}) { accessToken } }`,
		`{ userinfo { sub } }`,
	}
	h := newHarness(t, func(s *setup) { s.API.Limiter = fixedLimiter(1) })
	_, client := h.tenant("acme")
	// Spend the one unit of budget; from here on the caller is over the limit.
	if r := h.gql(client, fields[1], nil); r.codeAt("login") != "invalid_credentials" {
		t.Fatalf("first request: %s", r.Raw)
	}
	for _, q := range fields {
		for _, auth := range []string{"", client, adminKey} {
			if r := h.gql(auth, q, nil); len(r.Errors) != 1 || r.Errors[0].Extensions.Code != "rate_limited" {
				t.Errorf("%s: got %s, want rate_limited", q, r.Raw)
			}
		}
	}

	// The list above must name every such field of the schema.
	schema := graphql.MustParseSchema(graphqlapi.Schema, nil, graphql.UseStringDescriptions())
	credential := []string{"register", "login", "refresh", "logout", "introspectToken", "requestEmailVerification", "confirmEmail",
		"forgotPassword", "resetPassword", "authorize", "token", "userinfo"}
	for _, name := range credential {
		if !strings.Contains(strings.Join(fields, "\n"), " "+name) {
			t.Errorf("%s is not exercised", name)
		}
		q, m := schema.AST().Types["Query"].(*ast.ObjectTypeDefinition), schema.AST().Types["Mutation"].(*ast.ObjectTypeDefinition)
		if q.Fields.Get(name) == nil && m.Fields.Get(name) == nil {
			t.Errorf("%s is not a field of the schema", name)
		}
	}
}

// No type of the schema, input or output, has a field for a stored secret.
func TestSchemaExposesNoStoredSecrets(t *testing.T) {
	schema := graphql.MustParseSchema(graphqlapi.Schema, nil, graphql.UseStringDescriptions())
	// The only places a secret or a password may appear: arguments and input
	// fields a caller sends, and the one result field that carries a freshly
	// generated client secret.
	allowedOutput := map[string]bool{"ApplicationWithSecret.clientSecret": true}
	sensitive := func(name string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "secret") || strings.Contains(n, "password") || strings.Contains(n, "verifier")
	}
	names := 0
	check := func(where, name string, output bool) {
		names++
		if strings.Contains(strings.ToLower(name), "hash") {
			t.Errorf("%s: name contains \"hash\"", where)
		}
		if output && sensitive(name) && !allowedOutput[where] {
			t.Errorf("%s: a secret in a result type", where)
		}
	}
	for typeName, typ := range schema.AST().Types {
		if strings.HasPrefix(typeName, "__") {
			continue
		}
		switch typ := typ.(type) {
		case *ast.ObjectTypeDefinition:
			// The fields of Query and Mutation name operations
			// (changePassword), not data; their results are checked below
			// like every other type.
			operation := typeName == "Query" || typeName == "Mutation"
			for _, f := range typ.Fields {
				check(typeName+"."+f.Name, f.Name, !operation)
				for _, a := range f.Arguments {
					check(typeName+"."+f.Name+"("+a.Name.Name+")", a.Name.Name, false)
				}
			}
		case *ast.InputObject:
			for _, v := range typ.Values {
				check(typeName+"."+v.Name.Name, v.Name.Name, false)
			}
		}
	}
	if names < 200 {
		t.Fatalf("only %d names were checked; the schema walk is broken", names)
	}
	// The client secret is returned by the two operations that generate one, and by nothing else.
	for typeName, typ := range schema.AST().Types {
		obj, ok := typ.(*ast.ObjectTypeDefinition)
		if !ok {
			continue
		}
		for _, f := range obj.Fields {
			if strings.TrimSuffix(f.Type.String(), "!") == "ApplicationWithSecret" && f.Name != "createApplication" && f.Name != "rotateApplicationSecret" {
				t.Errorf("%s.%s returns a client secret", typeName, f.Name)
			}
		}
	}
}

// Whatever the schema says, the stored hashes must not be in any response.
func TestStoredSecretsNeverLeaveTheServer(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	uid, access, _ := h.user(client, "ada@example.com")
	clientID, secret, _ := strings.Cut(client, ":")

	ctx := context.Background()
	u, err := h.env.Store.GetUser(ctx, tid, uid)
	if err != nil {
		t.Fatal(err)
	}
	app, err := h.env.Store.GetApplicationByClientID(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "" || app.ClientSecretHash == "" {
		t.Fatal("the store holds no hashes; nothing to look for")
	}
	// Everything introspection lists for the types that describe a user or an application.
	fieldsOf := func(typeName string) string {
		r := h.ok(h.gql("", `query($n: String!) { __type(name: $n) { fields { name type { kind ofType { kind } } } } }`, M{"n": typeName}))
		var names []string
		for _, f := range r.at("__type.fields").([]any) {
			f := f.(map[string]any)
			kind := f["type"].(map[string]any)["kind"]
			if of, ok := f["type"].(map[string]any)["ofType"].(map[string]any); ok && kind == "NON_NULL" {
				kind = of["kind"]
			}
			if kind == "SCALAR" || kind == "LIST" {
				names = append(names, f["name"].(string))
			}
		}
		return strings.Join(names, " ")
	}
	userFields, appFields := fieldsOf("User"), fieldsOf("Application")
	for _, r := range []result{
		h.gql(access, `{ me { user { `+userFields+` } roles permissions } }`, nil),
		h.gql(adminKey, `query($t: ID!, $id: ID!) { user(tenantId: $t, id: $id) { `+userFields+` } users(tenantId: $t) { items { `+userFields+` } } }`, M{"t": tid, "id": uid}),
		h.gql(adminKey, `query($t: ID!, $id: ID!) { application(tenantId: $t, id: $id) { `+appFields+` } applications(tenantId: $t) { items { `+appFields+` } } }`, M{"t": tid, "id": app.ID}),
		h.gql(adminKey, `mutation($t: ID!, $id: ID!) { updateApplication(tenantId: $t, id: $id, input: {name: "renamed"}) { `+appFields+` } }`, M{"t": tid, "id": app.ID}),
		h.gql(adminKey, `query($t: ID!) { auditEvents(tenantId: $t, limit: 100) { items { type metadata targetId } } }`, M{"t": tid}),
		h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}),
	} {
		h.ok(r)
		for what, v := range map[string]string{"password hash": u.PasswordHash, "client secret hash": app.ClientSecretHash, "client secret": secret, "password": password} {
			if strings.Contains(r.Raw, v) {
				t.Errorf("%s in a response: %s", what, r.Raw)
			}
		}
	}
}

// failingStore breaks on demand, to see what a caller learns from a failure
// that is not a domain error.
type failingStore struct {
	store.Store
	fail func() error
}

func (s *failingStore) ListTenants(ctx context.Context, p store.Page) ([]*domain.Tenant, int, error) {
	if err := s.fail(); err != nil {
		return nil, 0, err
	}
	return s.Store.ListTenants(ctx, p)
}

func TestInternalErrorsAreMasked(t *testing.T) {
	const secret = "pq: password authentication failed for user keyora-prod at 10.0.0.5"
	st := &failingStore{Store: memory.New(), fail: func() error { return nil }}
	h := newHarness(t, func(s *setup) { s.Store = st })
	h.tenant("acme")

	check := func(name, requestID string) {
		t.Helper()
		r := h.gql(adminKey, `{ tenants { total } ok: tenant(id: "nope") { id } }`, nil, "X-Request-ID", requestID)
		if r.Status != 200 || r.codeAt("tenants") != "internal_error" || r.at("tenants") != nil {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
		for _, e := range r.Errors {
			if e.Extensions.Code == "internal_error" && (e.Message != "an internal error occurred" || e.Extensions.RequestID != requestID || e.Extensions.Details != nil) {
				t.Fatalf("%s: internal error shape: %+v", name, e)
			}
		}
		// The other field of the same request is unaffected.
		if r.codeAt("ok") != "not_found" {
			t.Fatalf("%s: sibling field: %s", name, r.Raw)
		}
		for _, leak := range []string{"pq:", "keyora-prod", "10.0.0.5", "goroutine", "failingStore", ".go:"} {
			if strings.Contains(r.Raw, leak) {
				t.Fatalf("%s: response leaks %q: %s", name, leak, r.Raw)
			}
		}
		// The operator, unlike the caller, gets the cause and the request ID.
		logs := h.logs.String()
		if !strings.Contains(logs, "request_id="+requestID) || !strings.Contains(logs, "keyora-prod") {
			t.Fatalf("%s: the failure was not logged with its request ID:\n%s", name, logs)
		}
	}

	st.fail = func() error { return errors.New(secret) }
	check("plain error", "trace-error-1")
	st.fail = func() error { return fmt.Errorf("list tenants: %w", errors.New(secret)) }
	check("wrapped error", "trace-error-2")
	st.fail = func() error { panic(secret) }
	check("panic", "trace-panic-3")

	// The server survives all of it.
	st.fail = func() error { return nil }
	h.ok(h.gql(adminKey, `{ tenants { total } }`, nil))
}
