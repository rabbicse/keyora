package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	"github.com/rabbicse/keyora/jwt"
)

var (
	ctx  = context.Background()
	meta = service.Meta{IP: "203.0.113.9", UserAgent: "test", RequestID: "req-1"}
)

const password = "correct horse battery"

func ptr[T any](v T) *T { return &v }

type world struct {
	*testutil.Env
	t      *testing.T
	tenant *domain.Tenant
	app    *domain.Application
	secret string
}

func newWorld(t *testing.T, mod func(*service.Options)) *world {
	t.Helper()
	env := testutil.NewEnv(t, memory.New(), mod)
	w := &world{Env: env, t: t}
	w.tenant, w.app, w.secret = w.newTenant("acme")
	return w
}

func (w *world) newTenant(slug string) (*domain.Tenant, *domain.Application, string) {
	w.t.Helper()
	tn, err := w.Svc.CreateTenant(ctx, service.TenantInput{Slug: &slug, Name: &slug}, meta)
	must(w.t, err)
	app, secret, err := w.Svc.CreateApplication(ctx, tn.ID, service.ApplicationInput{Name: ptr("web")}, meta)
	must(w.t, err)
	return tn, app, secret
}

func (w *world) register(email string) *domain.User {
	w.t.Helper()
	u, err := w.Svc.Register(ctx, w.app, service.RegisterInput{Email: email, Password: password, Name: "Ada"}, meta)
	must(w.t, err)
	return u
}

func (w *world) login(email string) *service.Tokens {
	w.t.Helper()
	tok, _, err := w.Svc.Login(ctx, w.app, email, password, meta)
	must(w.t, err)
	return tok
}

func (w *world) claims(access string) *jwt.Claims {
	w.t.Helper()
	c, err := jwt.Verify(access, w.Svc.Keys().PublicKey, jwt.Validation{Issuer: "https://id.test", Audience: w.app.ClientID, Now: w.Clock.Now})
	must(w.t, err)
	return c
}

func (w *world) events(typ string) int {
	_, n, _ := w.Store.ListAuditEvents(ctx, w.tenant.ID, store.AuditFilter{Type: typ}, store.Page{Limit: 1})
	return n
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}

func wantField(t *testing.T, err error, field string) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Kind != domain.KindInvalid || de.Details[field] == "" {
		t.Fatalf("got %v, want a validation error on %q", err, field)
	}
}

func TestRegisterAndLogin(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("  Ada@Example.COM ")
	if u.Email != "ada@example.com" || u.EmailVerified || u.TenantID != w.tenant.ID {
		t.Fatalf("unexpected user %+v", u)
	}
	stored, _ := w.Store.GetUser(ctx, w.tenant.ID, u.ID)
	if strings.Contains(stored.PasswordHash, password) || !strings.HasPrefix(stored.PasswordHash, "pbkdf2-sha256$") {
		t.Fatalf("password is not stored as a PBKDF2 hash: %q", stored.PasswordHash)
	}

	tok, logged, err := w.Svc.Login(ctx, w.app, "ADA@example.com", password, meta)
	must(t, err)
	if logged.LastLoginAt == nil || tok.TokenType != "Bearer" || tok.ExpiresIn != 900 || tok.RefreshToken == "" {
		t.Fatalf("unexpected login result %+v", tok)
	}
	c := w.claims(tok.AccessToken)
	if c.Subject != u.ID || c.TenantID != w.tenant.ID || c.SessionID != tok.SessionID || c.Email != u.Email || c.ClientID != w.app.ClientID {
		t.Fatalf("unexpected claims %+v", c)
	}
	if c.ExpiresAt-c.IssuedAt != 900 {
		t.Fatalf("access token lifetime is %ds, want 900", c.ExpiresAt-c.IssuedAt)
	}
	// Refresh tokens are opaque and only their hash is persisted.
	if strings.Count(tok.RefreshToken, ".") != 0 {
		t.Fatal("refresh token should be opaque, not a JWT")
	}
	if _, err := w.Store.GetRefreshTokenByHash(ctx, tok.RefreshToken); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("refresh token is stored in plaintext")
	}
	if w.events("user.registered") != 1 || w.events("user.login.succeeded") != 1 {
		t.Fatal("registration and login were not audited")
	}
}

func TestRegistrationValidation(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	_, err := w.Svc.Register(ctx, w.app, service.RegisterInput{Email: "ADA@example.com", Password: password}, meta)
	wantErr(t, err, domain.ErrEmailTaken)

	for _, email := range []string{"", "not-an-email", "a@b@c", "Ada <ada@example.com>", "ada@example.com, eve@example.com", strings.Repeat("a", 250) + "@x.io", "a\n@example.com"} {
		_, err := w.Svc.Register(ctx, w.app, service.RegisterInput{Email: email, Password: password}, meta)
		wantField(t, err, "email")
	}
	for _, pw := range []string{"", "short", "1234567", strings.Repeat("x", 300), "new@example.com"} {
		_, err := w.Svc.Register(ctx, w.app, service.RegisterInput{Email: "new@example.com", Password: pw}, meta)
		wantField(t, err, "password")
	}
	_, err = w.Svc.Register(ctx, w.app, service.RegisterInput{Email: "new@example.com", Password: password, Name: "bad\x00name"}, meta)
	wantField(t, err, "name")
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	_, _, wrongPw := w.Svc.Login(ctx, w.app, "ada@example.com", "wrong password!", meta)
	_, _, noUser := w.Svc.Login(ctx, w.app, "nobody@example.com", password, meta)
	_, _, badEmail := w.Svc.Login(ctx, w.app, "not-an-email", password, meta)
	for _, err := range []error{wrongPw, noUser, badEmail} {
		wantErr(t, err, domain.ErrInvalidCredentials)
		if err.Error() != wrongPw.Error() {
			t.Fatalf("responses differ and leak which accounts exist: %q vs %q", err, wrongPw)
		}
	}
}

func TestBruteForceLockout(t *testing.T) {
	w := newWorld(t, nil) // MaxFailedLogins: 3, LockoutDuration: 10m
	u := w.register("ada@example.com")
	for i := 0; i < 3; i++ {
		_, _, err := w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
		wantErr(t, err, domain.ErrInvalidCredentials)
	}
	// Even the correct password is refused while locked.
	_, _, err := w.Svc.Login(ctx, w.app, u.Email, password, meta)
	wantErr(t, err, domain.ErrAccountLocked)
	var de *domain.Error
	errors.As(err, &de)
	if de.Details["retry_after_seconds"] == "" {
		t.Fatal("lockout does not say when to retry")
	}
	if w.events("user.locked") != 1 {
		t.Fatal("lockout was not audited")
	}

	w.Clock.Advance(11 * time.Minute)
	// After expiry the counter restarts: one more mistake must not re-lock.
	_, _, err = w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
	wantErr(t, err, domain.ErrInvalidCredentials)
	w.login(u.Email)
	got, _ := w.Store.GetUser(ctx, w.tenant.ID, u.ID)
	if got.FailedLogins != 0 || got.LockedUntil != nil {
		t.Fatalf("successful login did not reset counters: %+v", got)
	}

	// An administrator can lift a lock early.
	for i := 0; i < 3; i++ {
		w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
	}
	_, err = w.Svc.UnlockUser(ctx, w.tenant.ID, u.ID, meta)
	must(t, err)
	w.login(u.Email)
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	first := w.login("ada@example.com")

	w.Clock.Advance(time.Minute)
	second, err := w.Svc.Refresh(ctx, w.app, first.RefreshToken, meta)
	must(t, err)
	if second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken || second.SessionID != first.SessionID {
		t.Fatal("refresh must rotate both tokens inside the same session")
	}
	third, err := w.Svc.Refresh(ctx, w.app, second.RefreshToken, meta)
	must(t, err)

	// Replaying a rotated token is treated as theft: the session dies,
	// including for whoever holds the newest, otherwise valid token.
	_, err = w.Svc.Refresh(ctx, w.app, first.RefreshToken, meta)
	wantErr(t, err, domain.ErrRefreshTokenReused)
	_, err = w.Svc.Refresh(ctx, w.app, third.RefreshToken, meta)
	if err == nil {
		t.Fatal("the session survived refresh token reuse")
	}
	if _, err := w.Svc.Authenticate(ctx, third.AccessToken); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("access token still accepted after its session was revoked: %v", err)
	}
	if w.events("token.reuse_detected") != 1 {
		t.Fatal("reuse was not audited")
	}

	for _, bad := range []string{"", "kyr_unknown", first.AccessToken} {
		_, err := w.Svc.Refresh(ctx, w.app, bad, meta)
		wantErr(t, err, domain.ErrInvalidRefreshToken)
	}
}

func TestConcurrentRefreshHasOneWinner(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	tok := w.login("ada@example.com")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.Svc.Refresh(ctx, w.app, tok.RefreshToken, meta); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent refreshes succeeded with one token, want exactly 1", ok)
	}
}

func TestRefreshExpiryAndSlidingSession(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	tok := w.login("ada@example.com")
	ttl := time.Duration(w.app.RefreshTokenTTL) * time.Second

	w.Clock.Advance(ttl - time.Hour)
	tok, err := w.Svc.Refresh(ctx, w.app, tok.RefreshToken, meta)
	must(t, err) // activity extends the session
	w.Clock.Advance(ttl - time.Hour)
	tok, err = w.Svc.Refresh(ctx, w.app, tok.RefreshToken, meta)
	must(t, err)
	w.Clock.Advance(ttl + time.Second)
	_, err = w.Svc.Refresh(ctx, w.app, tok.RefreshToken, meta)
	wantErr(t, err, domain.ErrInvalidRefreshToken)
}

func TestRefreshTokenIsBoundToItsApplication(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	tok := w.login("ada@example.com")
	other, _, err := w.Svc.CreateApplication(ctx, w.tenant.ID, service.ApplicationInput{Name: ptr("mobile")}, meta)
	must(t, err)
	_, err = w.Svc.Refresh(ctx, other, tok.RefreshToken, meta)
	wantErr(t, err, domain.ErrInvalidRefreshToken)
	must(t, w.Svc.Logout(ctx, other, tok.RefreshToken, meta)) // silently ignored
	if _, err := w.Svc.Authenticate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("another application was able to end the session: %v", err)
	}
}

func TestLogout(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	a, b := w.login("ada@example.com"), w.login("ada@example.com") // two devices
	must(t, w.Svc.Logout(ctx, w.app, a.RefreshToken, meta))
	must(t, w.Svc.Logout(ctx, w.app, a.RefreshToken, meta)) // idempotent
	must(t, w.Svc.Logout(ctx, w.app, "kyr_never-issued", meta))

	_, err := w.Svc.Refresh(ctx, w.app, a.RefreshToken, meta)
	if err == nil {
		t.Fatal("refresh token works after logout")
	}
	_, err = w.Svc.Authenticate(ctx, a.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
	if _, err := w.Svc.Authenticate(ctx, b.AccessToken); err != nil {
		t.Fatalf("logging out one device ended another: %v", err)
	}
	p, _ := w.Svc.Authenticate(ctx, b.AccessToken)
	must(t, w.Svc.LogoutSession(ctx, p, meta))
	_, err = w.Svc.Authenticate(ctx, b.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
}

func TestAuthenticateRejectsForgedAndStaleTokens(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("ada@example.com")
	tok := w.login("ada@example.com")
	if _, err := w.Svc.Authenticate(ctx, tok.AccessToken); err != nil {
		t.Fatal(err)
	}
	sign := func(mod func(*jwt.Claims)) string {
		c := *w.claims(tok.AccessToken)
		mod(&c)
		s, _ := w.Svc.Keys().Signer().Sign(c)
		return s
	}
	parts := strings.Split(tok.AccessToken, ".")
	cases := map[string]string{
		"garbage":            "not-a-token",
		"tampered signature": parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])),
		"wrong issuer":       sign(func(c *jwt.Claims) { c.Issuer = "https://evil.test" }),
		"other user's sid":   sign(func(c *jwt.Claims) { c.Subject = "someone-else" }),
		"other tenant":       sign(func(c *jwt.Claims) { c.TenantID = "another-tenant" }),
		"no session":         sign(func(c *jwt.Claims) { c.SessionID = "" }),
		"unknown session":    sign(func(c *jwt.Claims) { c.SessionID = "nope" }),
	}
	for name, token := range cases {
		if _, err := w.Svc.Authenticate(ctx, token); !errors.Is(err, domain.ErrInvalidToken) {
			t.Errorf("%s: got %v, want invalid_token", name, err)
		}
	}
	w.Clock.Advance(16 * time.Minute)
	_, err := w.Svc.Authenticate(ctx, tok.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken) // expired

	// Disabling a user cuts off even unexpired tokens.
	fresh := w.login("ada@example.com")
	_, err = w.Svc.UpdateUser(ctx, w.tenant.ID, u.ID, service.UserInput{Status: ptr(domain.StatusDisabled)}, meta)
	must(t, err)
	_, err = w.Svc.Authenticate(ctx, fresh.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
	_, _, err = w.Svc.Login(ctx, w.app, u.Email, password, meta)
	wantErr(t, err, domain.ErrAccountDisabled)
	_, _, err = w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
	wantErr(t, err, domain.ErrInvalidCredentials) // status only shown to the password holder
}

func TestRolesReachTokensAndIntrospection(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("ada@example.com")
	_, err := w.Svc.CreatePermission(ctx, w.tenant.ID, "orders:read", "", meta)
	must(t, err)
	_, err = w.Svc.CreatePermission(ctx, w.tenant.ID, "orders:write", "", meta)
	must(t, err)
	role, err := w.Svc.CreateRole(ctx, w.tenant.ID, "editor", "", []string{"orders:write", "orders:read"}, meta)
	must(t, err)

	before := w.login(u.Email)
	must(t, w.Svc.AssignRole(ctx, w.tenant.ID, u.ID, role.ID, meta))
	after := w.login(u.Email)

	if c := w.claims(before.AccessToken); len(c.Roles) != 0 {
		t.Fatal("token issued before the grant carries the role")
	}
	c := w.claims(after.AccessToken)
	if strings.Join(c.Roles, ",") != "editor" || strings.Join(c.Permissions, ",") != "orders:read,orders:write" {
		t.Fatalf("claims: roles=%v permissions=%v", c.Roles, c.Permissions)
	}

	// Introspection reflects the store, so it sees the grant on the old token too...
	in, err := w.Svc.Introspect(ctx, w.app, before.AccessToken)
	must(t, err)
	if !in.Active || strings.Join(in.Permissions, ",") != "orders:read,orders:write" || in.Subject != u.ID {
		t.Fatalf("introspection: %+v", in)
	}
	// ...and a revocation immediately, which a self-contained JWT cannot.
	must(t, w.Svc.UnassignRole(ctx, w.tenant.ID, u.ID, role.ID, meta))
	in, _ = w.Svc.Introspect(ctx, w.app, after.AccessToken)
	if !in.Active || len(in.Permissions) != 0 {
		t.Fatalf("revoked role still reported: %+v", in)
	}
	must(t, w.Svc.Logout(ctx, w.app, after.RefreshToken, meta))
	in, _ = w.Svc.Introspect(ctx, w.app, after.AccessToken)
	if in.Active || in.Subject != "" {
		t.Fatalf("logged-out token reported active or leaked claims: %+v", in)
	}
	for _, bad := range []string{"", "garbage", strings.Repeat("a.", 3)} {
		if in, _ := w.Svc.Introspect(ctx, w.app, bad); in.Active {
			t.Fatalf("%q reported active", bad)
		}
	}

	_, err = w.Svc.CreateRole(ctx, w.tenant.ID, "ghost", "", []string{"does:not-exist"}, meta)
	wantField(t, err, "permissions")
	if _, n, _ := w.Svc.ListRoles(ctx, w.tenant.ID, store.Page{Limit: 10}); n != 2 { // keyora-admin + editor
		t.Fatalf("a role with invalid permissions was left behind: %d roles", n)
	}
}

func TestReservedAdminObjectsAreProtected(t *testing.T) {
	w := newWorld(t, nil)
	roles, _, _ := w.Svc.ListRoles(ctx, w.tenant.ID, store.Page{Limit: 10})
	perms, _, _ := w.Svc.ListPermissions(ctx, w.tenant.ID, store.Page{Limit: 10})
	if len(roles) != 1 || roles[0].Name != domain.RoleAdmin || len(perms) != 1 || perms[0].Name != domain.PermissionAdmin {
		t.Fatalf("tenant was not seeded with its admin role: %+v %+v", roles, perms)
	}
	var de *domain.Error
	for name, err := range map[string]error{
		"delete role":       w.Svc.DeleteRole(ctx, w.tenant.ID, roles[0].ID, meta),
		"delete permission": w.Svc.DeletePermission(ctx, w.tenant.ID, perms[0].ID, meta),
		"rename role":       func() error { _, e := w.Svc.UpdateRole(ctx, w.tenant.ID, roles[0].ID, ptr("x"), nil, meta); return e }(),
		"strip permission": func() error {
			_, e := w.Svc.SetRolePermissions(ctx, w.tenant.ID, roles[0].ID, []string{}, meta)
			return e
		}(),
	} {
		if !errors.As(err, &de) || de.Kind != domain.KindForbidden {
			t.Errorf("%s: got %v, want forbidden", name, err)
		}
	}
	_, err := w.Svc.CreatePermission(ctx, w.tenant.ID, "Keyora:root", "", meta)
	wantField(t, err, "name")
}

func TestEmailVerification(t *testing.T) {
	w := newWorld(t, func(o *service.Options) {
		o.RequireEmailVerification = true
		o.EmailVerificationURL = "https://app.test/verify?token={token}"
	})
	u := w.register("ada@example.com")
	_, _, err := w.Svc.Login(ctx, w.app, u.Email, password, meta)
	wantErr(t, err, domain.ErrEmailNotVerified)
	_, _, err = w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
	wantErr(t, err, domain.ErrInvalidCredentials)

	msg, ok := w.Mail.Last(u.Email)
	if !ok || !strings.Contains(msg.Body, "https://app.test/verify?token=kyv_") {
		t.Fatalf("verification email missing or malformed: %+v", msg)
	}
	token := msg.Body[strings.Index(msg.Body, "kyv_"):]
	token = strings.TrimSpace(token)

	wantErr(t, w.Svc.ConfirmEmail(ctx, "kyv_wrong", meta), domain.ErrInvalidVerification)
	must(t, w.Svc.ConfirmEmail(ctx, token, meta))
	wantErr(t, w.Svc.ConfirmEmail(ctx, token, meta), domain.ErrInvalidVerification) // single use
	w.login(u.Email)

	// Re-sending is silent for verified and unknown addresses alike.
	sent := len(w.Mail.Messages)
	must(t, w.Svc.RequestEmailVerification(ctx, w.app, u.Email))
	must(t, w.Svc.RequestEmailVerification(ctx, w.app, "nobody@example.com"))
	if len(w.Mail.Messages) != sent {
		t.Fatal("verification email sent when none was due")
	}
}

func TestVerificationTokenExpires(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("ada@example.com")
	msg, _ := w.Mail.Last(u.Email)
	token := strings.TrimSpace(msg.Body[strings.Index(msg.Body, "kyv_"):])
	w.Clock.Advance(25 * time.Hour)
	wantErr(t, w.Svc.ConfirmEmail(ctx, token, meta), domain.ErrInvalidVerification)
}

func TestPasswordReset(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("ada@example.com")
	session := w.login(u.Email)
	for i := 0; i < 3; i++ { // lock the account
		w.Svc.Login(ctx, w.app, u.Email, "wrong password!", meta)
	}

	sent := len(w.Mail.Messages)
	must(t, w.Svc.ForgotPassword(ctx, w.app, "nobody@example.com", meta))
	if len(w.Mail.Messages) != sent {
		t.Fatal("reset email sent for an unknown address")
	}
	must(t, w.Svc.ForgotPassword(ctx, w.app, u.Email, meta))
	msg, _ := w.Mail.Last(u.Email)
	token := strings.TrimSpace(strings.SplitN(msg.Body[strings.Index(msg.Body, "kyp_"):], "\n", 2)[0])

	// A rejected password must not burn the token.
	wantField(t, w.Svc.ResetPassword(ctx, token, "short", meta), "password")
	// A verification token is not a reset token.
	vmsg := w.Mail.Messages[0]
	vtoken := strings.TrimSpace(vmsg.Body[strings.Index(vmsg.Body, "kyv_"):])
	wantErr(t, w.Svc.ResetPassword(ctx, vtoken, "a brand new password", meta), domain.ErrInvalidVerification)

	must(t, w.Svc.ResetPassword(ctx, token, "a brand new password", meta))
	wantErr(t, w.Svc.ResetPassword(ctx, token, "yet another password", meta), domain.ErrInvalidVerification)

	_, err := w.Svc.Authenticate(ctx, session.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken) // signed out everywhere
	_, _, err = w.Svc.Login(ctx, w.app, u.Email, password, meta)
	wantErr(t, err, domain.ErrInvalidCredentials) // old password is dead
	if _, _, err := w.Svc.Login(ctx, w.app, u.Email, "a brand new password", meta); err != nil {
		t.Fatalf("new password rejected (lock should be cleared by the reset): %v", err)
	}
	got, _ := w.Store.GetUser(ctx, w.tenant.ID, u.ID)
	if !got.EmailVerified {
		t.Fatal("a completed reset should mark the mailbox verified")
	}

	must(t, w.Svc.ForgotPassword(ctx, w.app, u.Email, meta))
	msg, _ = w.Mail.Last(u.Email)
	token = strings.TrimSpace(strings.SplitN(msg.Body[strings.Index(msg.Body, "kyp_"):], "\n", 2)[0])
	w.Clock.Advance(61 * time.Minute)
	wantErr(t, w.Svc.ResetPassword(ctx, token, "a brand new password", meta), domain.ErrInvalidVerification)
}

func TestChangePassword(t *testing.T) {
	w := newWorld(t, nil)
	u := w.register("ada@example.com")
	here, elsewhere := w.login(u.Email), w.login(u.Email)
	p, err := w.Svc.Authenticate(ctx, here.AccessToken)
	must(t, err)

	err = w.Svc.ChangePassword(ctx, p, "not my password", "a brand new password", meta)
	wantErr(t, err, domain.ErrInvalidCredentials)
	wantField(t, w.Svc.ChangePassword(ctx, p, password, "tiny", meta), "password")
	must(t, w.Svc.ChangePassword(ctx, p, password, "a brand new password", meta))

	if _, err := w.Svc.Authenticate(ctx, here.AccessToken); err != nil {
		t.Fatalf("the session that changed the password was signed out: %v", err)
	}
	_, err = w.Svc.Authenticate(ctx, elsewhere.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
}

func TestClientAuthentication(t *testing.T) {
	w := newWorld(t, nil)
	auth := func(id, secret, origin string, confidential bool) error {
		_, err := w.Svc.AuthenticateClient(ctx, id, secret, origin, confidential)
		return err
	}
	must(t, auth(w.app.ClientID, w.secret, "", true))
	for name, err := range map[string]error{
		"wrong secret":   auth(w.app.ClientID, "kys_wrong", "", false),
		"empty secret":   auth(w.app.ClientID, "", "", false),
		"unknown id":     auth("app_nope", w.secret, "", false),
		"empty id":       auth("", "", "", false),
		"secret as id":   auth(w.secret, w.secret, "", false),
		"hash as secret": auth(w.app.ClientID, w.app.ClientSecretHash, "", false),
	} {
		if !errors.Is(err, domain.ErrInvalidClient) {
			t.Errorf("%s: got %v, want invalid_client", name, err)
		}
	}

	spa, secret, err := w.Svc.CreateApplication(ctx, w.tenant.ID, service.ApplicationInput{Name: ptr("spa"), Type: ptr(domain.AppPublic),
		AllowedOrigins: &[]string{"https://app.example.com"}}, meta)
	must(t, err)
	if secret != "" || spa.ClientSecretHash != "" {
		t.Fatal("a public application was given a secret")
	}
	must(t, auth(spa.ClientID, "", "https://app.example.com", false))
	must(t, auth(spa.ClientID, "", "", false)) // non-browser caller
	wantErr(t, auth(spa.ClientID, "", "https://evil.example", false), domain.ErrOriginNotAllowed)
	wantErr(t, auth(spa.ClientID, "", "", true), domain.ErrInvalidClient) // cannot introspect

	// Rotating the secret kills the old one at once.
	_, rotated, err := w.Svc.RotateApplicationSecret(ctx, w.tenant.ID, w.app.ID, meta)
	must(t, err)
	wantErr(t, auth(w.app.ClientID, w.secret, "", false), domain.ErrInvalidClient)
	must(t, auth(w.app.ClientID, rotated, "", false))
	_, _, err = w.Svc.RotateApplicationSecret(ctx, w.tenant.ID, spa.ID, meta)
	if err == nil {
		t.Fatal("rotated the secret of a public application")
	}

	_, err = w.Svc.UpdateApplication(ctx, w.tenant.ID, w.app.ID, service.ApplicationInput{Status: ptr(domain.StatusDisabled)}, meta)
	must(t, err)
	wantErr(t, auth(w.app.ClientID, rotated, "", false), domain.ErrInvalidClient)
}

func TestSuspendedTenantIsCutOff(t *testing.T) {
	w := newWorld(t, nil)
	w.register("ada@example.com")
	tok := w.login("ada@example.com")
	_, err := w.Svc.UpdateTenant(ctx, w.tenant.ID, service.TenantInput{Status: ptr(domain.StatusSuspended)}, meta)
	must(t, err)
	_, err = w.Svc.AuthenticateClient(ctx, w.app.ClientID, w.secret, "", false)
	wantErr(t, err, domain.ErrInvalidClient)
	_, err = w.Svc.Authenticate(ctx, tok.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
}

func TestTenantIsolation(t *testing.T) {
	w := newWorld(t, nil)
	other, otherApp, _ := w.newTenant("beta")

	// The same email is two unrelated accounts in two tenants.
	a := w.register("same@example.com")
	b, err := w.Svc.Register(ctx, otherApp, service.RegisterInput{Email: "same@example.com", Password: "a different password"}, meta)
	must(t, err)
	if a.ID == b.ID || b.TenantID != other.ID {
		t.Fatal("tenants share a user")
	}
	_, _, err = w.Svc.Login(ctx, otherApp, "same@example.com", password, meta)
	wantErr(t, err, domain.ErrInvalidCredentials) // tenant A's password is useless in B

	tokA := w.login("same@example.com")
	// A token from tenant A is not introspectable by tenant B's application.
	in, err := w.Svc.Introspect(ctx, otherApp, tokA.AccessToken)
	must(t, err)
	if in.Active {
		t.Fatal("tenant B introspected tenant A's token")
	}
	_, err = w.Svc.Refresh(ctx, otherApp, tokA.RefreshToken, meta)
	wantErr(t, err, domain.ErrInvalidRefreshToken)

	// Management calls scoped to B cannot touch A's objects.
	_, err = w.Svc.GetUser(ctx, other.ID, a.ID)
	wantErr(t, err, domain.ErrNotFound)
	_, err = w.Svc.UpdateUser(ctx, other.ID, a.ID, service.UserInput{Status: ptr(domain.StatusDisabled)}, meta)
	wantErr(t, err, domain.ErrNotFound)
	wantErr(t, w.Svc.DeleteUser(ctx, other.ID, a.ID, meta), domain.ErrNotFound)
	wantErr(t, w.Svc.RevokeSession(ctx, other.ID, "", tokA.SessionID, meta), domain.ErrNotFound)
	_, err = w.Svc.GetApplication(ctx, other.ID, w.app.ID)
	wantErr(t, err, domain.ErrNotFound)
	_, _, err = w.Svc.RotateApplicationSecret(ctx, other.ID, w.app.ID, meta)
	wantErr(t, err, domain.ErrNotFound)

	rolesA, _, _ := w.Svc.ListRoles(ctx, w.tenant.ID, store.Page{Limit: 10})
	wantErr(t, w.Svc.AssignRole(ctx, other.ID, b.ID, rolesA[0].ID, meta), domain.ErrNotFound)

	p := &service.Principal{UserID: a.ID, TenantID: w.tenant.ID, Permissions: []string{domain.PermissionAdmin}}
	if !p.CanManage(w.tenant.ID) || p.CanManage(other.ID) {
		t.Fatal("a tenant administrator can manage another tenant")
	}
	if (&service.Principal{TenantID: w.tenant.ID, Permissions: []string{"orders:write"}}).CanManage(w.tenant.ID) {
		t.Fatal("a user without keyora:admin can manage the tenant")
	}
}

func TestClientCredentials(t *testing.T) {
	w := newWorld(t, nil)
	tok, err := w.Svc.ClientCredentials(ctx, w.app, meta)
	must(t, err)
	if tok.RefreshToken != "" || tok.SessionID != "" {
		t.Fatal("client credentials must not produce a refresh token or session")
	}
	c := w.claims(tok.AccessToken)
	if c.Subject != w.app.ClientID || len(c.Roles) != 0 {
		t.Fatalf("unexpected claims %+v", c)
	}
	in, _ := w.Svc.Introspect(ctx, w.app, tok.AccessToken)
	if !in.Active {
		t.Fatal("machine token not active")
	}
	// A machine token has no user and must not pass as one.
	_, err = w.Svc.Authenticate(ctx, tok.AccessToken)
	wantErr(t, err, domain.ErrInvalidToken)
	must(t, w.Svc.DeleteApplication(ctx, w.tenant.ID, w.app.ID, meta))
	other, _, _ := w.Svc.CreateApplication(ctx, w.tenant.ID, service.ApplicationInput{Name: ptr("api")}, meta)
	if in, _ := w.Svc.Introspect(ctx, other, tok.AccessToken); in.Active {
		t.Fatal("token of a deleted application still active")
	}
}

func TestApplicationValidation(t *testing.T) {
	w := newWorld(t, nil)
	create := func(in service.ApplicationInput) error {
		if in.Name == nil {
			in.Name = ptr("x" + time.Now().String())
		}
		_, _, err := w.Svc.CreateApplication(ctx, w.tenant.ID, in, meta)
		return err
	}
	wantField(t, create(service.ApplicationInput{Type: ptr("hybrid")}), "type")
	wantField(t, create(service.ApplicationInput{AllowedOrigins: &[]string{"https://a.test/path"}}), "allowed_origins")
	wantField(t, create(service.ApplicationInput{AllowedOrigins: &[]string{"*"}}), "allowed_origins")
	wantField(t, create(service.ApplicationInput{RedirectURIs: &[]string{"https://a.test/*"}}), "redirect_uris")
	wantField(t, create(service.ApplicationInput{RedirectURIs: &[]string{"/relative"}}), "redirect_uris")
	wantField(t, create(service.ApplicationInput{RedirectURIs: &[]string{"https://a.test/cb#frag"}}), "redirect_uris")
	wantField(t, create(service.ApplicationInput{AccessTokenTTL: ptr(int64(5))}), "access_token_ttl_seconds")
	wantField(t, create(service.ApplicationInput{AccessTokenTTL: ptr(int64(3600)), RefreshTokenTTL: ptr(int64(600))}), "refresh_token_ttl_seconds")
	must(t, create(service.ApplicationInput{RedirectURIs: &[]string{"https://a.test/cb", "com.example.app:/oauth"}, AllowedOrigins: &[]string{"http://localhost:3000"}}))

	err := create(service.ApplicationInput{Name: ptr("web")})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "name_taken" {
		t.Fatalf("duplicate name: %v", err)
	}
	_, err = w.Svc.UpdateApplication(ctx, w.tenant.ID, w.app.ID, service.ApplicationInput{Type: ptr(domain.AppPublic)}, meta)
	wantField(t, err, "type")
	_, err = w.Svc.CreateTenant(ctx, service.TenantInput{Slug: ptr("Not A Slug"), Name: ptr("x")}, meta)
	wantField(t, err, "slug")
	_, err = w.Svc.CreateTenant(ctx, service.TenantInput{Slug: ptr("acme"), Name: ptr("x")}, meta)
	if !errors.As(err, &de) || de.Code != "slug_taken" {
		t.Fatalf("duplicate slug: %v", err)
	}
}

func TestPasswordRehashOnLogin(t *testing.T) {
	st := memory.New()
	weak := testutil.NewEnv(t, st, func(o *service.Options) { o.PBKDF2Iterations = 1000 })
	slug := "acme"
	tn, err := weak.Svc.CreateTenant(ctx, service.TenantInput{Slug: &slug, Name: &slug}, meta)
	must(t, err)
	app, _, err := weak.Svc.CreateApplication(ctx, tn.ID, service.ApplicationInput{Name: ptr("web")}, meta)
	must(t, err)
	u, err := weak.Svc.Register(ctx, app, service.RegisterInput{Email: "ada@example.com", Password: password}, meta)
	must(t, err)

	strong := testutil.NewEnv(t, st, func(o *service.Options) { o.PBKDF2Iterations = 4000 })
	if _, _, err := strong.Svc.Login(ctx, app, u.Email, password, meta); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetUser(ctx, tn.ID, u.ID)
	if !strings.Contains(got.PasswordHash, "$i=4000$") {
		t.Fatalf("hash was not upgraded to the current work factor: %s", got.PasswordHash)
	}
	if _, _, err := strong.Svc.Login(ctx, app, u.Email, password, meta); err != nil {
		t.Fatalf("login fails after rehash: %v", err)
	}
}
