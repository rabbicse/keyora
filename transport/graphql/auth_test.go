package graphqlapi_test

import (
	"strings"
	"testing"
)

func TestSignUpSignInRefreshLogout(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")

	// RBAC setup through the management fields.
	h.ok(h.gql(adminKey, `mutation($t: ID!) { createPermission(tenantId: $t, name: "orders:read", description: "Read orders") { id } }`, M{"t": tid}))
	role := h.ok(h.gql(adminKey, `mutation($t: ID!) { createRole(tenantId: $t, name: "viewer", permissions: ["orders:read"]) { id } }`, M{"t": tid}))

	reg := h.ok(h.gql(client, `mutation {
		register(email: "ada@example.com", password: "`+password+`", name: "Ada") { id tenantId email name status emailVerified createdAt }
	}`, nil))
	if strings.Contains(reg.Raw, "pbkdf2") || strings.Contains(reg.Raw, password) {
		t.Fatalf("registration response leaks credential material: %s", reg.Raw)
	}
	uid := reg.str("register.id")
	if reg.str("register.tenantId") != tid || reg.str("register.status") != "active" || reg.at("register.emailVerified") != false {
		t.Fatalf("registered user: %s", reg.Raw)
	}
	h.ok(h.gql(adminKey, `mutation($t: ID!, $u: ID!, $r: ID!) { assignRole(tenantId: $t, userId: $u, roleId: $r) }`,
		M{"t": tid, "u": uid, "r": role.str("createRole.id")}))

	login := h.ok(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}))
	access, refresh := login.str("login.tokens.accessToken"), login.str("login.tokens.refreshToken")
	if login.str("login.tokens.tokenType") != "Bearer" || login.num("login.tokens.expiresIn") <= 0 || login.str("login.user.id") != uid {
		t.Fatalf("login: %s", login.Raw)
	}

	me := h.ok(h.gql(access, `{ me { user { id email name } roles permissions } }`, nil))
	if me.str("me.user.id") != uid || me.str("me.roles.0") != "viewer" || me.str("me.permissions.0") != "orders:read" {
		t.Fatalf("profile: %s", me.Raw)
	}
	upd := h.ok(h.gql(access, `mutation { updateMe(name: "Ada L.") { name } }`, nil))
	if upd.str("updateMe.name") != "Ada L." {
		t.Fatalf("updateMe: %s", upd.Raw)
	}
	sessions := h.ok(h.gql(access, `{ mySessions { items { id userId ip userAgent expiresAt revokedAt } total limit offset } }`, nil))
	if sessions.num("mySessions.total") != 1 || sessions.num("mySessions.limit") != 20 || sessions.num("mySessions.offset") != 0 ||
		sessions.str("mySessions.items.0.id") != login.str("login.tokens.sessionId") || sessions.at("mySessions.items.0.revokedAt") != nil {
		t.Fatalf("sessions: %s", sessions.Raw)
	}

	const introspect = `query($token: String!) {
		introspectToken(token: $token) { active subject tenantId clientId sessionId email roles permissions issuer expiresAt issuedAt }
	}`
	in := h.ok(h.gql(client, introspect, M{"token": access}))
	clientID, _, _ := strings.Cut(client, ":")
	if in.at("introspectToken.active") != true || in.str("introspectToken.subject") != uid || in.str("introspectToken.tenantId") != tid ||
		in.str("introspectToken.clientId") != clientID || in.str("introspectToken.issuer") != "https://id.test" ||
		in.str("introspectToken.roles.0") != "viewer" || in.str("introspectToken.expiresAt") <= in.str("introspectToken.issuedAt") {
		t.Fatalf("introspection: %s", in.Raw)
	}

	const refreshMutation = `mutation($rt: String!) { refresh(refreshToken: $rt) { accessToken refreshToken } }`
	rotated := h.ok(h.gql(client, refreshMutation, M{"rt": refresh}))
	newAccess, newRefresh := rotated.str("refresh.accessToken"), rotated.str("refresh.refreshToken")
	if newRefresh == refresh {
		t.Fatal("refresh token was not rotated")
	}

	out := h.ok(h.gql(client, `mutation($rt: String!) { logout(refreshToken: $rt) }`, M{"rt": newRefresh}))
	if out.at("logout") != true {
		t.Fatalf("logout: %s", out.Raw)
	}
	h.fails(h.gql(newAccess, `{ me { user { id } } }`, nil), "invalid_token")
	in = h.ok(h.gql(client, introspect, M{"token": newAccess}))
	if in.at("introspectToken.active") != false || in.at("introspectToken.subject") != nil || len(in.at("introspectToken.roles").([]any)) != 0 {
		t.Fatalf("logged-out token still active: %s", in.Raw)
	}
	h.fails(h.gql(client, refreshMutation, M{"rt": newRefresh}), "invalid_refresh_token")

	audit := h.ok(h.gql(adminKey, `query($t: ID!) {
		auditEvents(tenantId: $t, type: "user.logout") { items { type actorType actorId targetId requestId metadata createdAt } total }
	}`, M{"t": tid}))
	if audit.num("auditEvents.total") != 1 || audit.str("auditEvents.items.0.actorId") != uid || audit.str("auditEvents.items.0.requestId") == "" {
		t.Fatalf("audit trail: %s", audit.Raw)
	}
}

func TestLogoutWithAccessToken(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	_, access, refresh := h.user(client, "ada@example.com")

	h.ok(h.gql(access, `mutation { logout }`, nil))
	h.fails(h.gql(access, `{ me { user { id } } }`, nil), "invalid_token")
	h.fails(h.gql(client, `mutation($rt: String!) { refresh(refreshToken: $rt) { accessToken } }`, M{"rt": refresh}), "invalid_refresh_token")
	h.fails(h.gql("", `mutation { logout }`, nil), "unauthenticated")
}

// Application credentials travel as HTTP Basic or as arguments; Basic wins.
func TestClientCredentialSources(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	id, secret, _ := strings.Cut(client, ":")
	h.user(client, "ada@example.com")

	const login = `mutation($id: String, $secret: String) {
		login(email: "ada@example.com", password: "` + password + `", clientId: $id, clientSecret: $secret) { tokens { accessToken } }
	}`
	h.ok(h.gql("", login, M{"id": id, "secret": secret}))
	h.ok(h.gql(client, login, nil))
	h.ok(h.gql(client, login, M{"id": id, "secret": "wrong"}))
	h.fails(h.gql(id+":wrong", login, M{"id": id, "secret": secret}), "invalid_client")
	h.fails(h.gql("", login, nil), "invalid_client")
	h.fails(h.gql("", login, M{"id": id}), "invalid_client")
	h.fails(h.gql("", login, M{"id": "kyc_unknown", "secret": secret}), "invalid_client")

	// A request has one Authorization header. With a bearer token in it, the
	// application's credentials go in the arguments, and both kinds of field
	// work in one document.
	access := h.ok(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password})).str("login.tokens.accessToken")
	both := h.ok(h.gql(access, `query($token: String!, $id: String, $secret: String) {
		me { user { email } }
		introspectToken(token: $token, clientId: $id, clientSecret: $secret) { active }
	}`, M{"token": access, "id": id, "secret": secret}))
	if both.str("me.user.email") != "ada@example.com" || both.at("introspectToken.active") != true {
		t.Fatalf("bearer token with credentials as arguments: %s", both.Raw)
	}

	// Introspection needs a confidential application; a public one is refused.
	spa := h.ok(h.gql(adminKey, `mutation($t: ID!) {
		createApplication(tenantId: $t, input: {name: "spa", type: "public", allowedOrigins: ["https://app.example.com"]}) { application { clientId } clientSecret }
	}`, M{"t": tid}))
	if spa.at("createApplication.clientSecret") != nil {
		t.Fatalf("public application received a secret: %s", spa.Raw)
	}
	spaID := spa.str("createApplication.application.clientId")
	h.fails(h.gql("", `query($id: String) { introspectToken(token: "x", clientId: $id) { active } }`, M{"id": spaID}), "invalid_client")

	// The Origin header reaches the gate: a public application may only be
	// used from a browser origin registered on it.
	h.ok(h.gql("", login, M{"id": spaID}))
	h.ok(h.gql("", login, M{"id": spaID}, "Origin", "https://app.example.com"))
	h.fails(h.gql("", login, M{"id": spaID}, "Origin", "https://evil.example"), "origin_not_allowed")
}

func TestEmailVerificationAndPasswordReset(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	h.user(client, "ada@example.com")
	tokenFrom := func(prefix string) string {
		t.Helper()
		msg, ok := h.env.Mail.Last("ada@example.com")
		if !ok {
			t.Fatal("no email sent")
		}
		return strings.Fields(msg.Body[strings.Index(msg.Body, prefix):])[0]
	}
	const confirm = `mutation($token: String!) { confirmEmail(token: $token) }`
	first := tokenFrom("kyv_")
	h.fails(h.gql("", confirm, M{"token": "kyv_wrong"}), "invalid_verification_token")

	// A second verification email can be requested while the address is unverified.
	h.ok(h.gql(client, `mutation { requestEmailVerification(email: "ada@example.com") }`, nil))
	second := tokenFrom("kyv_")
	if second == first {
		t.Fatal("no new verification email was sent")
	}
	h.ok(h.gql("", confirm, M{"token": second}))
	h.fails(h.gql("", confirm, M{"token": second}), "invalid_verification_token")

	// Identical answers for known and unknown addresses.
	const forgot = `mutation($email: String!) { forgotPassword(email: $email) }`
	known := h.ok(h.gql(client, forgot, M{"email": "ada@example.com"}))
	unknown := h.ok(h.gql(client, forgot, M{"email": "nobody@example.com"}))
	if known.Raw != unknown.Raw {
		t.Fatalf("forgotPassword reveals account existence: %q vs %q", known.Raw, unknown.Raw)
	}
	h.fails(h.gql("", forgot, M{"email": "ada@example.com"}), "invalid_client")

	const reset = `mutation($token: String!, $pw: String!) { resetPassword(token: $token, newPassword: $pw) }`
	token := tokenFrom("kyp_")
	weak := h.fails(h.gql("", reset, M{"token": token, "pw": "x"}), "validation_failed")
	if len(weak.Errors[0].Extensions.Details) == 0 {
		t.Fatalf("validation error without details: %s", weak.Raw)
	}
	h.ok(h.gql("", reset, M{"token": token, "pw": "a brand new password"}))
	h.fails(h.gql("", reset, M{"token": token, "pw": "another new password"}), "invalid_verification_token")
	h.fails(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}), "invalid_credentials")
	h.ok(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": "a brand new password"}))
}

func TestSelfService(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	_, first, _ := h.user(client, "ada@example.com")
	second := h.ok(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}))
	_, other, _ := h.user(client, "bob@example.com")

	list := h.ok(h.gql(first, `{ mySessions(limit: 1, offset: 1) { items { id } total limit offset } }`, nil))
	if list.num("mySessions.total") != 2 || len(list.at("mySessions.items").([]any)) != 1 || list.num("mySessions.limit") != 1 || list.num("mySessions.offset") != 1 {
		t.Fatalf("paged sessions: %s", list.Raw)
	}

	// A session can be revoked by its owner and by nobody else.
	const revoke = `mutation($id: ID!) { revokeMySession(sessionId: $id) }`
	sid := second.str("login.tokens.sessionId")
	h.fails(h.gql(other, revoke, M{"id": sid}), "not_found")
	h.ok(h.gql(first, revoke, M{"id": sid}))
	h.fails(h.gql(second.str("login.tokens.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")

	// Changing the password needs the current one and ends the other sessions.
	third := h.ok(h.gql(client, loginMutation, M{"email": "ada@example.com", "password": password}))
	const change = `mutation($cur: String!, $next: String!) { changePassword(currentPassword: $cur, newPassword: $next) }`
	h.fails(h.gql(first, change, M{"cur": "not the password", "next": "a brand new password"}), "invalid_credentials")
	h.ok(h.gql(first, change, M{"cur": password, "next": "a brand new password"}))
	h.ok(h.gql(first, `{ me { user { id } } }`, nil))
	h.fails(h.gql(third.str("login.tokens.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")

	// Every self-service field needs a user: no token, a bad token and the
	// root key (which has no user identity) are all refused.
	for _, q := range []string{
		`{ me { user { id } } }`,
		`{ mySessions { total } }`,
		`mutation { updateMe(name: "x") { id } }`,
		`mutation { changePassword(currentPassword: "a", newPassword: "b") }`,
		`mutation { revokeMySession(sessionId: "x") }`,
		`mutation { logout }`,
		`{ userinfo { sub } }`,
	} {
		for token, want := range map[string]string{"": "unauthenticated", "not-a-token": "invalid_token", adminKey: "forbidden"} {
			if r := h.gql(token, q, nil); len(r.Errors) != 1 || r.Errors[0].Extensions.Code != want {
				t.Errorf("%s with token %.12q: got %v, want %s", q, token, r.codes(), want)
			}
		}
	}
}

// The fields of a mutation run in order, and each one identifies the caller
// again: a token revoked by one field is refused by the next.
func TestMutationFieldsRunInOrder(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	_, access, _ := h.user(client, "ada@example.com")

	r := h.gql(access, `mutation {
		before: updateMe(name: "first") { name }
		logout
		after: updateMe(name: "second") { name }
	}`, nil)
	if r.str("before.name") != "first" || r.at("logout") != true || r.at("after") != nil || r.codeAt("after") != "invalid_token" || len(r.Errors) != 1 {
		t.Fatalf("mutation order: %s", r.Raw)
	}
}
