package grpcapi_test

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/rabbicse/keyora/jwt"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

func TestSignUpSignInRefreshLogout(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")

	// RBAC setup through the management API.
	must(h.roles.CreatePermission(h.root(), &keyorapb.CreatePermissionRequest{TenantId: tid, Name: "orders:read", Description: "Read orders"}))(t)
	role := must(h.roles.CreateRole(h.root(), &keyorapb.CreateRoleRequest{TenantId: tid, Name: "viewer", Permissions: []string{"orders:read"}}))(t)

	reg := must(h.auth.Register(h.basic(c), &keyorapb.RegisterRequest{Email: "ada@example.com", Password: password, Name: "Ada"}))(t)
	uid := reg.GetUser().GetId()
	if u := reg.GetUser(); uid == "" || u.GetEmail() != "ada@example.com" || u.GetTenantId() != tid || u.GetStatus() != "active" ||
		u.GetEmailVerified() || u.GetCreatedAt() == nil || u.GetLastLoginAt() != nil {
		t.Fatalf("registered user: %v", u)
	}
	if text := prototext.Format(reg); strings.Contains(text, "pbkdf2") || strings.Contains(text, password) {
		t.Fatalf("registration response leaks credential material: %s", text)
	}
	must(h.users.AssignUserRole(h.root(), &keyorapb.AssignUserRoleRequest{TenantId: tid, UserId: uid, RoleId: role.GetRole().GetId()}))(t)

	login := must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password}))(t)
	tok := login.GetTokens()
	if tok.GetTokenType() != "Bearer" || tok.GetExpiresIn() <= 0 || tok.GetRefreshExpiresIn() <= tok.GetExpiresIn() ||
		tok.GetSessionId() == "" || tok.GetIdToken() != "" || login.GetUser().GetId() != uid || login.GetUser().GetLastLoginAt() == nil {
		t.Fatalf("login response: %v", login)
	}

	// The access token is the same kind of token the REST API issues: a
	// resource server verifies it with the key ring's public keys.
	claims, err := jwt.Verify(tok.GetAccessToken(), h.env.Svc.Keys().PublicKey,
		jwt.Validation{Issuer: "https://id.test", Audience: c.id, Now: h.env.Clock.Now})
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if !claims.HasRole("viewer") || !claims.HasPermission("orders:read") || claims.TenantID != tid || claims.Subject != uid {
		t.Fatalf("claims: %+v", claims)
	}

	me := must(h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{}))(t)
	if me.GetUser().GetId() != uid || strings.Join(me.GetRoles(), ",") != "viewer" || strings.Join(me.GetPermissions(), ",") != "orders:read" {
		t.Fatalf("profile: %v", me)
	}
	name := "Ada L."
	if upd := must(h.account.UpdateMe(h.bearer(tok.GetAccessToken()), &keyorapb.UpdateMeRequest{Name: &name}))(t); upd.GetUser().GetName() != name {
		t.Fatalf("updated profile: %v", upd)
	}
	_, err = h.account.UpdateMe(h.bearer(tok.GetAccessToken()), &keyorapb.UpdateMeRequest{})
	if md := expect(t, err, codes.InvalidArgument, "validation_failed"); md["name"] == "" {
		t.Fatalf("validation error does not name the field: %v", md)
	}
	if list := must(h.account.ListMySessions(h.bearer(tok.GetAccessToken()), &keyorapb.ListMySessionsRequest{}))(t); list.GetTotal() != 1 ||
		len(list.GetSessions()) != 1 || list.GetSessions()[0].GetId() != tok.GetSessionId() || list.GetSessions()[0].GetRevokedAt() != nil {
		t.Fatalf("sessions: %v", list)
	}

	in := must(h.auth.Introspect(h.basic(c), &keyorapb.IntrospectRequest{Token: tok.GetAccessToken()}))(t)
	if !in.GetActive() || in.GetSubject() != uid || in.GetTenantId() != tid || in.GetClientId() != c.id || in.GetSessionId() != tok.GetSessionId() ||
		in.GetEmail() != "ada@example.com" || in.GetIssuer() != "https://id.test" || strings.Join(in.GetRoles(), ",") != "viewer" ||
		in.GetExpiresAt().GetSeconds() != claims.ExpiresAt || in.GetIssuedAt().GetSeconds() != claims.IssuedAt {
		t.Fatalf("introspection: %v", in)
	}

	rotated := must(h.auth.Refresh(h.basic(c), &keyorapb.RefreshRequest{RefreshToken: tok.GetRefreshToken()}))(t).GetTokens()
	if rotated.GetRefreshToken() == tok.GetRefreshToken() || rotated.GetSessionId() != tok.GetSessionId() {
		t.Fatalf("refresh did not rotate inside the session: %v", rotated)
	}
	// A refresh token works once; a second use revokes the session.
	_, err = h.auth.Refresh(h.basic(c), &keyorapb.RefreshRequest{RefreshToken: tok.GetRefreshToken()})
	expect(t, err, codes.Unauthenticated, "refresh_token_reused")
	_, err = h.account.GetMe(h.bearer(rotated.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")

	// Sign in again and sign out with the refresh token.
	tok = must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password}))(t).GetTokens()
	must(h.auth.Logout(h.basic(c), &keyorapb.LogoutRequest{RefreshToken: tok.GetRefreshToken()}))(t)
	_, err = h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	if in := must(h.auth.Introspect(h.basic(c), &keyorapb.IntrospectRequest{Token: tok.GetAccessToken()}))(t); in.GetActive() || in.GetSubject() != "" {
		t.Fatalf("logged-out token still active: %v", in)
	}
	_, err = h.auth.Refresh(h.basic(c), &keyorapb.RefreshRequest{RefreshToken: tok.GetRefreshToken()})
	expect(t, err, codes.Unauthenticated, "invalid_refresh_token")
	// Logging out with a token that does not exist still succeeds.
	must(h.auth.Logout(h.basic(c), &keyorapb.LogoutRequest{RefreshToken: "kyr_unknown"}))(t)

	events := must(h.audit.ListAuditEvents(h.root(), &keyorapb.ListAuditEventsRequest{TenantId: tid, Type: "user.logout"}))(t)
	if events.GetTotal() != 1 || events.GetEvents()[0].GetTargetId() != uid || events.GetEvents()[0].GetMetadata()["session_id"] != tok.GetSessionId() {
		t.Fatalf("audit trail: %v", events)
	}
}

func TestLogoutWithAccessToken(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.tenant("acme")
	_, tok := h.user(c, "ada@example.com")

	must(h.auth.Logout(h.bearer(tok.GetAccessToken()), &keyorapb.LogoutRequest{}))(t)
	_, err := h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.auth.Refresh(h.basic(c), &keyorapb.RefreshRequest{RefreshToken: tok.GetRefreshToken()})
	expect(t, err, codes.Unauthenticated, "invalid_refresh_token")
	_, err = h.auth.Logout(h.ctx(), &keyorapb.LogoutRequest{})
	expect(t, err, codes.Unauthenticated, "unauthenticated")
	// The root key has no session to end.
	_, err = h.auth.Logout(h.root(), &keyorapb.LogoutRequest{})
	expect(t, err, codes.PermissionDenied, "forbidden")
}

func TestApplicationCredentials(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.tenant("acme")
	const email = "ada@example.com"
	login := func(id, secret string) *keyorapb.LoginRequest {
		return &keyorapb.LoginRequest{ClientId: id, ClientSecret: secret, Email: email, Password: password}
	}

	// In the message fields, or as Basic credentials in the metadata.
	must(h.auth.Register(h.ctx(), &keyorapb.RegisterRequest{ClientId: c.id, ClientSecret: c.secret, Email: email, Password: password}))(t)
	must(h.auth.Login(h.ctx(), login(c.id, c.secret)))(t)
	must(h.auth.Login(h.basic(c), login("", "")))(t)
	must(h.auth.Login(h.ctx("authorization", "basic "+strings.TrimPrefix(basicValue(c), "Basic ")), login("", "")))(t)

	// Basic wins when both are present.
	must(h.auth.Login(h.basic(c), login(c.id, "wrong")))(t)
	_, err := h.auth.Login(h.basic(client{c.id, "wrong"}), login(c.id, c.secret))
	expect(t, err, codes.Unauthenticated, "invalid_client")

	for name, call := range map[string]func() error{
		"no credentials": func() error { _, err := h.auth.Login(h.ctx(), login("", "")); return err },
		"wrong secret":   func() error { _, err := h.auth.Login(h.basic(client{c.id, "wrong"}), login("", "")); return err },
		"no secret":      func() error { _, err := h.auth.Login(h.ctx(), login(c.id, "")); return err },
		"unknown client": func() error { _, err := h.auth.Login(h.ctx(), login("app_unknown", c.secret)); return err },
		// The admin key is not an application credential.
		"admin key":       func() error { _, err := h.auth.Login(h.root(), login("", "")); return err },
		"malformed basic": func() error { _, err := h.auth.Login(h.ctx("authorization", "Basic !!!"), login("", "")); return err },
	} {
		t.Run(name, func(t *testing.T) { expect(t, call(), codes.Unauthenticated, "invalid_client") })
	}

	// Introspection is for confidential applications only.
	tid, _ := h.tenant("beta")
	spa := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "spa", Type: "public",
		AllowedOrigins: []string{"https://app.example.com"}}))(t)
	if spa.GetClientSecret() != "" {
		t.Fatal("a public application was given a secret")
	}
	pub := &keyorapb.RegisterRequest{ClientId: spa.GetApplication().GetClientId(), Email: email, Password: password}
	_, err = h.auth.Introspect(h.ctx(), &keyorapb.IntrospectRequest{ClientId: pub.GetClientId(), Token: "x"})
	expect(t, err, codes.Unauthenticated, "invalid_client")

	// A public application called from a browser must come from one of its origins.
	_, err = h.auth.Register(h.ctx("origin", "https://evil.example"), pub)
	expect(t, err, codes.PermissionDenied, "origin_not_allowed")
	must(h.auth.Register(h.ctx("origin", "https://app.example.com"), pub))(t)
}

func TestSessionSelfService(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.tenant("acme")
	_, laptop := h.user(c, "ada@example.com")
	phone := must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password}))(t).GetTokens()
	_, other := h.user(c, "bob@example.com")
	ada, bob := h.bearer(laptop.GetAccessToken()), h.bearer(other.GetAccessToken())

	if list := must(h.account.ListMySessions(ada, &keyorapb.ListMySessionsRequest{}))(t); list.GetTotal() != 2 {
		t.Fatalf("want 2 device sessions: %v", list)
	}
	if list := must(h.account.ListMySessions(ada, &keyorapb.ListMySessionsRequest{Limit: 1, Offset: 1}))(t); list.GetTotal() != 2 || len(list.GetSessions()) != 1 {
		t.Fatalf("paging: %v", list)
	}
	// Bob cannot end Ada's session.
	_, err := h.account.RevokeMySession(bob, &keyorapb.RevokeMySessionRequest{SessionId: phone.GetSessionId()})
	expect(t, err, codes.NotFound, "not_found")
	must(h.account.RevokeMySession(ada, &keyorapb.RevokeMySessionRequest{SessionId: phone.GetSessionId()}))(t)
	_, err = h.account.GetMe(h.bearer(phone.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	must(h.account.GetMe(ada, &keyorapb.GetMeRequest{}))(t)

	_, err = h.account.ChangePassword(ada, &keyorapb.ChangePasswordRequest{CurrentPassword: "wrong", NewPassword: "a brand new password"})
	expect(t, err, codes.Unauthenticated, "invalid_credentials")
	_, err = h.account.ChangePassword(ada, &keyorapb.ChangePasswordRequest{CurrentPassword: password, NewPassword: "short"})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	must(h.account.ChangePassword(ada, &keyorapb.ChangePasswordRequest{CurrentPassword: password, NewPassword: "a brand new password"}))(t)
	must(h.account.GetMe(ada, &keyorapb.GetMeRequest{}))(t) // the session that changed the password survives
	_, err = h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password})
	expect(t, err, codes.Unauthenticated, "invalid_credentials")
	must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: "a brand new password"}))(t)
}

func TestAccountLockout(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")
	uid, _ := h.user(c, "ada@example.com")
	for _, guess := range []string{"guess number a", "guess number b", "guess number c"} {
		_, err := h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: guess})
		expect(t, err, codes.Unauthenticated, "invalid_credentials")
	}
	// Locked now, even with the right password; the error says for how long.
	_, err := h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password})
	if md := expect(t, err, codes.FailedPrecondition, "account_locked"); md["retry_after_seconds"] == "" {
		t.Fatalf("locked error has no retry_after_seconds: %v", md)
	}
	if u := must(h.users.GetUser(h.root(), &keyorapb.GetUserRequest{TenantId: tid, Id: uid}))(t); u.GetUser().GetLockedUntil() == nil {
		t.Fatalf("locked user has no locked_until: %v", u)
	}
	if u := must(h.users.UnlockUser(h.root(), &keyorapb.UnlockUserRequest{TenantId: tid, Id: uid}))(t); u.GetUser().GetLockedUntil() != nil {
		t.Fatalf("unlocked user is still locked: %v", u)
	}
	must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: password}))(t)
}

func TestEmailVerificationAndPasswordReset(t *testing.T) {
	h := newHarness(t, nil)
	tid, c := h.tenant("acme")
	uid, _ := h.user(c, "ada@example.com")
	tokenFrom := func(prefix string) string {
		t.Helper()
		msg, ok := h.env.Mail.Last("ada@example.com")
		if !ok || !strings.Contains(msg.Body, prefix) {
			t.Fatalf("no email carrying a %s token was sent", prefix)
		}
		return strings.Fields(msg.Body[strings.Index(msg.Body, prefix):])[0]
	}

	_, err := h.auth.ConfirmEmail(h.ctx(), &keyorapb.ConfirmEmailRequest{Token: "kyv_wrong"})
	expect(t, err, codes.InvalidArgument, "invalid_verification_token")
	first := tokenFrom("kyv_")
	must(h.auth.RequestEmailVerification(h.basic(c), &keyorapb.RequestEmailVerificationRequest{Email: "ada@example.com"}))(t)
	if tokenFrom("kyv_") == first {
		t.Fatal("no new verification email was sent")
	}
	must(h.auth.ConfirmEmail(h.ctx(), &keyorapb.ConfirmEmailRequest{Token: tokenFrom("kyv_")}))(t)
	if u := must(h.users.GetUser(h.root(), &keyorapb.GetUserRequest{TenantId: tid, Id: uid}))(t); !u.GetUser().GetEmailVerified() {
		t.Fatal("email not marked as verified")
	}

	// Identical answers for known and unknown addresses.
	sent := len(h.env.Mail.Messages)
	must(h.auth.ForgotPassword(h.basic(c), &keyorapb.ForgotPasswordRequest{Email: "nobody@example.com"}))(t)
	must(h.auth.RequestEmailVerification(h.basic(c), &keyorapb.RequestEmailVerificationRequest{Email: "nobody@example.com"}))(t)
	if len(h.env.Mail.Messages) != sent {
		t.Fatal("email sent to an address without an account")
	}
	must(h.auth.ForgotPassword(h.basic(c), &keyorapb.ForgotPasswordRequest{Email: "ada@example.com"}))(t)
	_, err = h.auth.ForgotPassword(h.ctx(), &keyorapb.ForgotPasswordRequest{Email: "ada@example.com"})
	expect(t, err, codes.Unauthenticated, "invalid_client")

	reset := tokenFrom("kyp_")
	_, err = h.auth.ResetPassword(h.ctx(), &keyorapb.ResetPasswordRequest{Token: reset, NewPassword: "x"})
	expect(t, err, codes.InvalidArgument, "validation_failed")
	must(h.auth.ResetPassword(h.ctx(), &keyorapb.ResetPasswordRequest{Token: reset, NewPassword: "a brand new password"}))(t)
	_, err = h.auth.ResetPassword(h.ctx(), &keyorapb.ResetPasswordRequest{Token: reset, NewPassword: "another new password"})
	expect(t, err, codes.InvalidArgument, "invalid_verification_token")
	must(h.auth.Login(h.basic(c), &keyorapb.LoginRequest{Email: "ada@example.com", Password: "a brand new password"}))(t)
}
