// Package storetest is the conformance suite every store.Store must pass.
// Running one suite against every backend is what keeps them interchangeable.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/store"
)

var ctx = context.Background()

func ts(offset time.Duration) time.Time {
	return time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC).Add(offset)
}

type fixture struct {
	t  *testing.T
	st store.Store
}

func (f fixture) tenant(slug string) *domain.Tenant {
	f.t.Helper()
	tn := &domain.Tenant{ID: security.NewID(), Slug: slug, Name: slug, Status: domain.StatusActive, CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(f.t, f.st.CreateTenant(ctx, tn))
	return tn
}

func (f fixture) user(tenantID, email string) *domain.User {
	f.t.Helper()
	u := &domain.User{ID: security.NewID(), TenantID: tenantID, Email: email, Name: "N", PasswordHash: "h",
		Status: domain.StatusActive, CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(f.t, f.st.CreateUser(ctx, u))
	return u
}

func (f fixture) app(tenantID, name string) *domain.Application {
	f.t.Helper()
	a := &domain.Application{ID: security.NewID(), TenantID: tenantID, Name: name, Type: domain.AppConfidential,
		ClientID: "app_" + security.NewID(), ClientSecretHash: "x", RedirectURIs: []string{"https://a.test/cb"},
		AllowedOrigins: []string{"https://" + name + ".test"}, AccessTokenTTL: 900, RefreshTokenTTL: 3600,
		Status: domain.StatusActive, CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(f.t, f.st.CreateApplication(ctx, a))
	return a
}

func (f fixture) session(u *domain.User, a *domain.Application) *domain.Session {
	f.t.Helper()
	s := &domain.Session{ID: security.NewID(), TenantID: u.TenantID, UserID: u.ID, ApplicationID: a.ID, IP: "1.2.3.4",
		UserAgent: "ua", CreatedAt: ts(0), LastUsedAt: ts(0), ExpiresAt: ts(time.Hour)}
	must(f.t, f.st.CreateSession(ctx, s))
	return s
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

// Run executes the suite. newStore must return an empty store each call.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	tests := map[string]func(*testing.T, fixture){
		"Tenants":              testTenants,
		"Applications":         testApplications,
		"Users":                testUsers,
		"LoginCounters":        testLoginCounters,
		"RolesAndPermissions":  testRoles,
		"Sessions":             testSessions,
		"RefreshTokens":        testRefreshTokens,
		"RefreshTokenRace":     testRefreshRace,
		"VerificationTokens":   testVerificationTokens,
		"AuthorizationCodes":   testAuthorizationCodes,
		"LegacyCredentials":    testLegacyCredentials,
		"Audit":                testAudit,
		"TenantIsolation":      testIsolation,
		"CascadeAndExpiry":     testCascade,
		"HostileInputIsStored": testHostileInput,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			must(t, st.Ping(ctx))
			fn(t, fixture{t: t, st: st})
		})
	}
}

func testTenants(t *testing.T, f fixture) {
	a := f.tenant("acme")
	wantErr(t, f.st.CreateTenant(ctx, &domain.Tenant{ID: security.NewID(), Slug: "acme", Name: "x", Status: "active", CreatedAt: ts(0), UpdatedAt: ts(0)}), domain.ErrConflict)
	got, err := f.st.GetTenant(ctx, a.ID)
	must(t, err)
	if got.Slug != "acme" || !got.CreatedAt.Equal(ts(0)) {
		t.Fatalf("unexpected tenant %+v", got)
	}
	_, err = f.st.GetTenant(ctx, "missing")
	wantErr(t, err, domain.ErrNotFound)

	got.Status, got.UpdatedAt = domain.StatusSuspended, ts(time.Minute)
	must(t, f.st.UpdateTenant(ctx, got))
	got, _ = f.st.GetTenant(ctx, a.ID)
	if got.Status != domain.StatusSuspended {
		t.Fatal("status not updated")
	}
	f.tenant("beta")
	list, total, err := f.st.ListTenants(ctx, store.Page{Limit: 1})
	must(t, err)
	if total != 2 || len(list) != 1 {
		t.Fatalf("pagination: total=%d len=%d", total, len(list))
	}
}

func testApplications(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	a := f.app(tn.ID, "web")
	dup := *a
	dup.ID, dup.ClientID = security.NewID(), "other"
	wantErr(t, f.st.CreateApplication(ctx, &dup), domain.ErrConflict) // same name in tenant

	got, err := f.st.GetApplicationByClientID(ctx, a.ClientID)
	must(t, err)
	if got.ID != a.ID || len(got.RedirectURIs) != 1 || got.AllowedOrigins[0] != "https://web.test" || got.ClientSecretHash != "x" {
		t.Fatalf("unexpected application %+v", got)
	}
	got.AllowedOrigins, got.Status, got.ClientSecretHash = []string{"https://new.test"}, domain.StatusDisabled, "y"
	must(t, f.st.UpdateApplication(ctx, got))
	got, _ = f.st.GetApplication(ctx, tn.ID, a.ID)
	if got.Status != domain.StatusDisabled || got.ClientSecretHash != "y" {
		t.Fatal("application not updated")
	}
	origins, err := f.st.ListAllowedOrigins(ctx)
	must(t, err)
	if len(origins) != 0 {
		t.Fatalf("disabled applications must not contribute origins, got %v", origins)
	}
	_, total, _ := f.st.ListApplications(ctx, tn.ID, store.Page{Limit: 10})
	if total != 1 {
		t.Fatalf("total=%d", total)
	}
	must(t, f.st.DeleteApplication(ctx, tn.ID, a.ID))
	wantErr(t, f.st.DeleteApplication(ctx, tn.ID, a.ID), domain.ErrNotFound)
	missing := *a
	missing.ID, missing.ClientID, missing.TenantID = security.NewID(), "z", "no-such-tenant"
	wantErr(t, f.st.CreateApplication(ctx, &missing), domain.ErrNotFound)
}

func testUsers(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u := f.user(tn.ID, "ada@example.com")
	dup := *u
	dup.ID = security.NewID()
	wantErr(t, f.st.CreateUser(ctx, &dup), domain.ErrConflict)

	got, err := f.st.GetUserByEmail(ctx, tn.ID, "ada@example.com")
	must(t, err)
	if got.ID != u.ID || got.EmailVerified || got.LockedUntil != nil || got.LastLoginAt != nil {
		t.Fatalf("unexpected user %+v", got)
	}
	got.Name, got.EmailVerified, got.PasswordHash = "Ada", true, "h2"
	must(t, f.st.UpdateUser(ctx, got))
	got, _ = f.st.GetUser(ctx, tn.ID, u.ID)
	if got.Name != "Ada" || !got.EmailVerified || got.PasswordHash != "h2" {
		t.Fatal("user not updated")
	}
	for i := 0; i < 5; i++ {
		x := f.user(tn.ID, fmt.Sprintf("u%d@example.com", i))
		if i == 0 {
			x.Status = domain.StatusDisabled
			must(t, f.st.UpdateUser(ctx, x))
		}
	}
	list, total, err := f.st.ListUsers(ctx, tn.ID, store.UserFilter{}, store.Page{Limit: 2, Offset: 4})
	must(t, err)
	if total != 6 || len(list) != 2 {
		t.Fatalf("pagination: total=%d len=%d", total, len(list))
	}
	_, total, _ = f.st.ListUsers(ctx, tn.ID, store.UserFilter{Email: "ADA"}, store.Page{Limit: 10})
	if total != 1 {
		t.Fatalf("email filter total=%d", total)
	}
	_, total, _ = f.st.ListUsers(ctx, tn.ID, store.UserFilter{Email: "%"}, store.Page{Limit: 10})
	if total != 0 {
		t.Fatalf("LIKE wildcard must be matched literally, total=%d", total)
	}
	_, total, _ = f.st.ListUsers(ctx, tn.ID, store.UserFilter{Status: domain.StatusDisabled}, store.Page{Limit: 10})
	if total != 1 {
		t.Fatalf("status filter total=%d", total)
	}
	must(t, f.st.DeleteUser(ctx, tn.ID, u.ID))
	_, err = f.st.GetUser(ctx, tn.ID, u.ID)
	wantErr(t, err, domain.ErrNotFound)
}

func testLoginCounters(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u := f.user(tn.ID, "ada@example.com")
	for want := 1; want <= 3; want++ {
		n, err := f.st.IncrementFailedLogins(ctx, tn.ID, u.ID)
		must(t, err)
		if n != want {
			t.Fatalf("count=%d want %d", n, want)
		}
	}
	must(t, f.st.LockUser(ctx, tn.ID, u.ID, ts(time.Hour)))
	got, _ := f.st.GetUser(ctx, tn.ID, u.ID)
	if got.LockedUntil == nil || !got.LockedUntil.Equal(ts(time.Hour)) || got.FailedLogins != 3 {
		t.Fatalf("lock not stored: %+v", got)
	}
	// UpdateUser must not clobber the counters.
	got.Name = "changed"
	must(t, f.st.UpdateUser(ctx, got))
	login := ts(2 * time.Hour)
	must(t, f.st.ClearLoginFailures(ctx, tn.ID, u.ID, &login))
	got, _ = f.st.GetUser(ctx, tn.ID, u.ID)
	if got.LockedUntil != nil || got.FailedLogins != 0 || got.LastLoginAt == nil || !got.LastLoginAt.Equal(login) {
		t.Fatalf("counters not cleared: %+v", got)
	}
	_, err := f.st.IncrementFailedLogins(ctx, tn.ID, "missing")
	wantErr(t, err, domain.ErrNotFound)

	// Concurrent failures must all be counted.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.st.IncrementFailedLogins(ctx, tn.ID, u.ID) }()
	}
	wg.Wait()
	got, _ = f.st.GetUser(ctx, tn.ID, u.ID)
	if got.FailedLogins != 20 {
		t.Fatalf("lost updates: failed_logins=%d want 20", got.FailedLogins)
	}
}

func testRoles(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u := f.user(tn.ID, "ada@example.com")
	perm := func(name string) *domain.Permission {
		p := &domain.Permission{ID: security.NewID(), TenantID: tn.ID, Name: name, CreatedAt: ts(0)}
		must(t, f.st.CreatePermission(ctx, p))
		return p
	}
	read, _ := perm("orders:read"), perm("orders:write")
	wantErr(t, f.st.CreatePermission(ctx, &domain.Permission{ID: security.NewID(), TenantID: tn.ID, Name: "orders:read", CreatedAt: ts(0)}), domain.ErrConflict)

	role := &domain.Role{ID: security.NewID(), TenantID: tn.ID, Name: "editor", CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(t, f.st.CreateRole(ctx, role))
	wantErr(t, f.st.CreateRole(ctx, &domain.Role{ID: security.NewID(), TenantID: tn.ID, Name: "editor", CreatedAt: ts(0), UpdatedAt: ts(0)}), domain.ErrConflict)

	must(t, f.st.SetRolePermissions(ctx, tn.ID, role.ID, []string{"orders:write", "orders:read", "orders:read"}))
	wantErr(t, f.st.SetRolePermissions(ctx, tn.ID, role.ID, []string{"nope"}), domain.ErrNotFound)
	got, err := f.st.GetRole(ctx, tn.ID, role.ID)
	must(t, err)
	if fmt.Sprint(got.Permissions) != "[orders:read orders:write]" {
		t.Fatalf("permissions=%v (a failed set must not change them)", got.Permissions)
	}

	must(t, f.st.AssignRole(ctx, tn.ID, u.ID, role.ID, ts(0)))
	must(t, f.st.AssignRole(ctx, tn.ID, u.ID, role.ID, ts(0))) // idempotent
	wantErr(t, f.st.AssignRole(ctx, tn.ID, u.ID, "missing", ts(0)), domain.ErrNotFound)
	roles, err := f.st.ListUserRoles(ctx, tn.ID, u.ID)
	must(t, err)
	if len(roles) != 1 || len(roles[0].Permissions) != 2 {
		t.Fatalf("user roles=%+v", roles)
	}

	must(t, f.st.DeletePermission(ctx, tn.ID, read.ID))
	got, _ = f.st.GetRole(ctx, tn.ID, role.ID)
	if fmt.Sprint(got.Permissions) != "[orders:write]" {
		t.Fatalf("deleting a permission must detach it from roles, got %v", got.Permissions)
	}
	got.Name = "writer"
	must(t, f.st.UpdateRole(ctx, got))
	list, total, _ := f.st.ListRoles(ctx, tn.ID, store.Page{Limit: 10})
	if total != 1 || list[0].Name != "writer" || len(list[0].Permissions) != 1 {
		t.Fatalf("roles=%+v", list)
	}
	must(t, f.st.UnassignRole(ctx, tn.ID, u.ID, role.ID))
	wantErr(t, f.st.UnassignRole(ctx, tn.ID, u.ID, role.ID), domain.ErrNotFound)
	must(t, f.st.AssignRole(ctx, tn.ID, u.ID, role.ID, ts(0)))
	must(t, f.st.DeleteRole(ctx, tn.ID, role.ID))
	roles, _ = f.st.ListUserRoles(ctx, tn.ID, u.ID)
	if len(roles) != 0 {
		t.Fatal("deleting a role must unassign it")
	}
}

func testSessions(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u, a := f.user(tn.ID, "ada@example.com"), f.app(tn.ID, "web")
	s1, s2, s3 := f.session(u, a), f.session(u, a), f.session(u, a)

	must(t, f.st.TouchSession(ctx, s1.ID, ts(time.Minute), ts(2*time.Hour)))
	got, err := f.st.GetSession(ctx, s1.ID)
	must(t, err)
	if !got.ExpiresAt.Equal(ts(2*time.Hour)) || !got.LastUsedAt.Equal(ts(time.Minute)) || got.RevokedAt != nil {
		t.Fatalf("unexpected session %+v", got)
	}
	must(t, f.st.RevokeSession(ctx, s2.ID, ts(time.Minute)))
	must(t, f.st.RevokeSession(ctx, s2.ID, ts(time.Hour))) // keeps the first timestamp
	got, _ = f.st.GetSession(ctx, s2.ID)
	if got.RevokedAt == nil || !got.RevokedAt.Equal(ts(time.Minute)) || got.Active(ts(2*time.Minute)) {
		t.Fatalf("revocation wrong: %+v", got)
	}
	wantErr(t, f.st.RevokeSession(ctx, "missing", ts(0)), domain.ErrNotFound)

	_, total, _ := f.st.ListSessions(ctx, tn.ID, store.SessionFilter{UserID: u.ID}, store.Page{Limit: 10})
	if total != 3 {
		t.Fatalf("total=%d", total)
	}
	_, total, _ = f.st.ListSessions(ctx, tn.ID, store.SessionFilter{ActiveOnly: true, Now: ts(90 * time.Minute)}, store.Page{Limit: 10})
	if total != 1 { // s1 was extended; s2 revoked; s3 expired
		t.Fatalf("active total=%d want 1", total)
	}
	n, err := f.st.RevokeUserSessions(ctx, tn.ID, u.ID, s3.ID, ts(time.Minute))
	must(t, err)
	if n != 1 {
		t.Fatalf("revoked %d sessions, want 1 (s1 only)", n)
	}
	got, _ = f.st.GetSession(ctx, s3.ID)
	if got.RevokedAt != nil {
		t.Fatal("excepted session was revoked")
	}
}

func testRefreshTokens(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	s := f.session(f.user(tn.ID, "ada@example.com"), f.app(tn.ID, "web"))
	tok := &domain.RefreshToken{ID: security.NewID(), SessionID: s.ID, TokenHash: "hash-1", CreatedAt: ts(0), ExpiresAt: ts(time.Hour)}
	must(t, f.st.CreateRefreshToken(ctx, tok))
	wantErr(t, f.st.CreateRefreshToken(ctx, &domain.RefreshToken{ID: security.NewID(), SessionID: s.ID, TokenHash: "hash-1", CreatedAt: ts(0), ExpiresAt: ts(time.Hour)}), domain.ErrConflict)

	got, reused, err := f.st.ConsumeRefreshToken(ctx, "hash-1", ts(time.Minute))
	must(t, err)
	if reused || got.SessionID != s.ID || got.UsedAt == nil {
		t.Fatalf("first consume: reused=%v tok=%+v", reused, got)
	}
	got, reused, err = f.st.ConsumeRefreshToken(ctx, "hash-1", ts(2*time.Minute))
	must(t, err)
	if !reused || !got.UsedAt.Equal(ts(time.Minute)) {
		t.Fatalf("second consume must report reuse and keep first used_at: reused=%v tok=%+v", reused, got)
	}
	_, _, err = f.st.ConsumeRefreshToken(ctx, "unknown", ts(0))
	wantErr(t, err, domain.ErrNotFound)
	_, err = f.st.GetRefreshTokenByHash(ctx, "unknown")
	wantErr(t, err, domain.ErrNotFound)
}

func testRefreshRace(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	s := f.session(f.user(tn.ID, "ada@example.com"), f.app(tn.ID, "web"))
	must(t, f.st.CreateRefreshToken(ctx, &domain.RefreshToken{ID: security.NewID(), SessionID: s.ID, TokenHash: "race", CreatedAt: ts(0), ExpiresAt: ts(time.Hour)}))
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, reused, err := f.st.ConsumeRefreshToken(ctx, "race", ts(time.Minute))
			if err == nil && !reused {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("%d callers consumed the same refresh token; exactly 1 must win", winners)
	}
}

func testVerificationTokens(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u := f.user(tn.ID, "ada@example.com")
	mk := func(hash string, exp time.Time) {
		must(t, f.st.CreateVerificationToken(ctx, &domain.VerificationToken{ID: security.NewID(), TenantID: tn.ID, UserID: u.ID,
			Purpose: domain.PurposePasswordReset, TokenHash: hash, CreatedAt: ts(0), ExpiresAt: exp}))
	}
	mk("v1", ts(time.Hour))
	mk("expired", ts(time.Minute))

	_, err := f.st.ConsumeVerificationToken(ctx, "v1", domain.PurposeEmailVerification, ts(2*time.Minute))
	wantErr(t, err, domain.ErrNotFound) // wrong purpose
	got, err := f.st.ConsumeVerificationToken(ctx, "v1", domain.PurposePasswordReset, ts(2*time.Minute))
	must(t, err)
	if got.UserID != u.ID || got.TenantID != tn.ID {
		t.Fatalf("unexpected token %+v", got)
	}
	_, err = f.st.ConsumeVerificationToken(ctx, "v1", domain.PurposePasswordReset, ts(3*time.Minute))
	wantErr(t, err, domain.ErrNotFound) // single use
	_, err = f.st.ConsumeVerificationToken(ctx, "expired", domain.PurposePasswordReset, ts(2*time.Minute))
	wantErr(t, err, domain.ErrNotFound)
}

func testAuthorizationCodes(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u, a := f.user(tn.ID, "ada@example.com"), f.app(tn.ID, "web")
	s := f.session(u, a)
	mk := func(hash string) *domain.AuthorizationCode {
		c := &domain.AuthorizationCode{ID: security.NewID(), CodeHash: hash, TenantID: tn.ID, ApplicationID: a.ID, UserID: u.ID,
			SessionID: s.ID, RedirectURI: "https://a.test/cb", CodeChallenge: "challenge", Scope: "profile", Nonce: "n-1",
			CreatedAt: ts(0), ExpiresAt: ts(time.Minute)}
		must(t, f.st.CreateAuthorizationCode(ctx, c))
		return c
	}
	mk("code-1")
	wantErr(t, f.st.CreateAuthorizationCode(ctx, &domain.AuthorizationCode{ID: security.NewID(), CodeHash: "code-1", TenantID: tn.ID,
		ApplicationID: a.ID, UserID: u.ID, SessionID: s.ID, CreatedAt: ts(0), ExpiresAt: ts(time.Minute)}), domain.ErrConflict)

	got, reused, err := f.st.ConsumeAuthorizationCode(ctx, "code-1", ts(time.Second))
	must(t, err)
	if reused || got.SessionID != s.ID || got.RedirectURI != "https://a.test/cb" || got.CodeChallenge != "challenge" ||
		got.Scope != "profile" || got.Nonce != "n-1" || got.ApplicationID != a.ID || !got.ExpiresAt.Equal(ts(time.Minute)) {
		t.Fatalf("first consume: reused=%v code=%+v", reused, got)
	}
	_, reused, err = f.st.ConsumeAuthorizationCode(ctx, "code-1", ts(2*time.Second))
	must(t, err)
	if !reused {
		t.Fatal("second consume must report reuse")
	}
	_, _, err = f.st.ConsumeAuthorizationCode(ctx, "unknown", ts(0))
	wantErr(t, err, domain.ErrNotFound)

	// Exactly one of many concurrent redemptions wins.
	mk("race")
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, reused, err := f.st.ConsumeAuthorizationCode(ctx, "race", ts(time.Second)); err == nil && !reused {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("%d callers redeemed the same authorization code; exactly 1 must win", winners)
	}

	mk("purge-me")
	if _, err := f.st.DeleteExpired(ctx, ts(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.st.ConsumeAuthorizationCode(ctx, "purge-me", ts(0))
	wantErr(t, err, domain.ErrNotFound)
}

func testLegacyCredentials(t *testing.T, f fixture) {
	a, b := f.tenant("acme"), f.tenant("beta")
	u, other := f.user(a.ID, "ada@example.com"), f.user(b.ID, "bob@example.com")
	cred := &domain.LegacyCredential{UserID: u.ID, TenantID: a.ID, Username: "ada", Salt: []byte{0, 1, 2, 255}, Verifier: []byte("verifier-bytes\x00\xff"), CreatedAt: ts(0)}
	must(t, f.st.CreateLegacyCredential(ctx, cred))
	got, err := f.st.GetLegacyCredential(ctx, a.ID, "ada")
	must(t, err)
	if got.UserID != u.ID || string(got.Salt) != string(cred.Salt) || string(got.Verifier) != string(cred.Verifier) {
		t.Fatalf("credential not round-tripped: %+v", got)
	}
	u2 := f.user(a.ID, "eve@example.com")
	wantErr(t, f.st.CreateLegacyCredential(ctx, &domain.LegacyCredential{UserID: u2.ID, TenantID: a.ID, Username: "ada", CreatedAt: ts(0)}), domain.ErrConflict)
	// The same username is free in another tenant, and invisible across tenants.
	must(t, f.st.CreateLegacyCredential(ctx, &domain.LegacyCredential{UserID: other.ID, TenantID: b.ID, Username: "ada", Salt: []byte{9}, Verifier: []byte{9}, CreatedAt: ts(0)}))
	if got, _ := f.st.GetLegacyCredential(ctx, b.ID, "ada"); got.UserID != other.ID {
		t.Fatal("credential lookup crossed tenants")
	}
	// A credential cannot be attached to a user of another tenant.
	wantErr(t, f.st.CreateLegacyCredential(ctx, &domain.LegacyCredential{UserID: u2.ID, TenantID: b.ID, Username: "x", CreatedAt: ts(0)}), domain.ErrNotFound)
	_, err = f.st.GetLegacyCredential(ctx, a.ID, "nobody")
	wantErr(t, err, domain.ErrNotFound)
	must(t, f.st.DeleteUser(ctx, a.ID, u.ID))
	_, err = f.st.GetLegacyCredential(ctx, a.ID, "ada")
	wantErr(t, err, domain.ErrNotFound)
}

func testAudit(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	for i := 0; i < 3; i++ {
		typ := "user.login.succeeded"
		if i == 2 {
			typ = "user.locked"
		}
		must(t, f.st.AppendAuditEvent(ctx, &domain.AuditEvent{ID: security.NewID(), TenantID: tn.ID, Type: typ, ActorType: "user",
			ActorID: "u1", Metadata: map[string]string{"k": "v"}, CreatedAt: ts(time.Duration(i) * time.Second)}))
	}
	list, total, err := f.st.ListAuditEvents(ctx, tn.ID, store.AuditFilter{}, store.Page{Limit: 2})
	must(t, err)
	if total != 3 || len(list) != 2 || list[0].Type != "user.locked" || list[0].Metadata["k"] != "v" {
		t.Fatalf("audit list wrong (newest first expected): total=%d %+v", total, list)
	}
	_, total, _ = f.st.ListAuditEvents(ctx, tn.ID, store.AuditFilter{Type: "user.locked", ActorID: "u1"}, store.Page{Limit: 10})
	if total != 1 {
		t.Fatalf("filtered total=%d", total)
	}
}

// testIsolation proves that an ID from one tenant is useless under another.
func testIsolation(t *testing.T, f fixture) {
	a, b := f.tenant("acme"), f.tenant("beta")
	ua, ub := f.user(a.ID, "same@example.com"), f.user(b.ID, "same@example.com") // same email, different tenants
	appA := f.app(a.ID, "web")
	f.app(b.ID, "web") // same name allowed across tenants
	roleA := &domain.Role{ID: security.NewID(), TenantID: a.ID, Name: "admin", CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(t, f.st.CreateRole(ctx, roleA))
	permA := &domain.Permission{ID: security.NewID(), TenantID: a.ID, Name: "secret:read", CreatedAt: ts(0)}
	must(t, f.st.CreatePermission(ctx, permA))
	roleB := &domain.Role{ID: security.NewID(), TenantID: b.ID, Name: "admin", CreatedAt: ts(0), UpdatedAt: ts(0)}
	must(t, f.st.CreateRole(ctx, roleB))

	_, err := f.st.GetUser(ctx, b.ID, ua.ID)
	wantErr(t, err, domain.ErrNotFound)
	_, err = f.st.GetApplication(ctx, b.ID, appA.ID)
	wantErr(t, err, domain.ErrNotFound)
	_, err = f.st.GetRole(ctx, b.ID, roleA.ID)
	wantErr(t, err, domain.ErrNotFound)

	wantErr(t, f.st.DeleteUser(ctx, b.ID, ua.ID), domain.ErrNotFound)
	wantErr(t, f.st.DeleteApplication(ctx, b.ID, appA.ID), domain.ErrNotFound)
	wantErr(t, f.st.DeleteRole(ctx, b.ID, roleA.ID), domain.ErrNotFound)
	wantErr(t, f.st.DeletePermission(ctx, b.ID, permA.ID), domain.ErrNotFound)
	wantErr(t, f.st.LockUser(ctx, b.ID, ua.ID, ts(time.Hour)), domain.ErrNotFound)

	hijack := *ua
	hijack.TenantID, hijack.Name = b.ID, "hijacked"
	wantErr(t, f.st.UpdateUser(ctx, &hijack), domain.ErrNotFound)

	// A role from tenant A cannot be granted to a user of tenant B, in either framing.
	wantErr(t, f.st.AssignRole(ctx, b.ID, ub.ID, roleA.ID, ts(0)), domain.ErrNotFound)
	wantErr(t, f.st.AssignRole(ctx, a.ID, ub.ID, roleA.ID, ts(0)), domain.ErrNotFound)
	// Tenant B's role cannot reference tenant A's permission.
	wantErr(t, f.st.SetRolePermissions(ctx, b.ID, roleB.ID, []string{"secret:read"}), domain.ErrNotFound)
	wantErr(t, f.st.SetRolePermissions(ctx, b.ID, roleA.ID, []string{}), domain.ErrNotFound)

	must(t, f.st.AssignRole(ctx, a.ID, ua.ID, roleA.ID, ts(0)))
	if roles, _ := f.st.ListUserRoles(ctx, b.ID, ua.ID); len(roles) != 0 {
		t.Fatal("roles leaked across tenants")
	}
	f.session(ua, appA)
	for name, total := range map[string]func() int{
		"users": func() int { _, n, _ := f.st.ListUsers(ctx, b.ID, store.UserFilter{}, store.Page{Limit: 10}); return n },
		"sessions": func() int {
			_, n, _ := f.st.ListSessions(ctx, b.ID, store.SessionFilter{}, store.Page{Limit: 10})
			return n
		},
		"roles": func() int { _, n, _ := f.st.ListRoles(ctx, b.ID, store.Page{Limit: 10}); return n },
	} {
		want := map[string]int{"users": 1, "sessions": 0, "roles": 1}[name]
		if got := total(); got != want {
			t.Fatalf("tenant B sees %d %s, want %d", got, name, want)
		}
	}
	if n, _ := f.st.RevokeUserSessions(ctx, b.ID, ua.ID, "", ts(0)); n != 0 {
		t.Fatal("revoked another tenant's sessions")
	}
}

func testCascade(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	u, a := f.user(tn.ID, "ada@example.com"), f.app(tn.ID, "web")
	s := f.session(u, a)
	must(t, f.st.CreateRefreshToken(ctx, &domain.RefreshToken{ID: security.NewID(), SessionID: s.ID, TokenHash: "c1", CreatedAt: ts(0), ExpiresAt: ts(time.Hour)}))
	must(t, f.st.DeleteUser(ctx, tn.ID, u.ID))
	_, err := f.st.GetSession(ctx, s.ID)
	wantErr(t, err, domain.ErrNotFound)
	_, err = f.st.GetRefreshTokenByHash(ctx, "c1")
	wantErr(t, err, domain.ErrNotFound)

	u2 := f.user(tn.ID, "bob@example.com")
	old := f.session(u2, a)
	must(t, f.st.CreateRefreshToken(ctx, &domain.RefreshToken{ID: security.NewID(), SessionID: old.ID, TokenHash: "c2", CreatedAt: ts(0), ExpiresAt: ts(time.Hour)}))
	must(t, f.st.TouchSession(ctx, old.ID, ts(0), ts(time.Minute)))
	keep := f.session(u2, a)
	n, err := f.st.DeleteExpired(ctx, ts(30*time.Minute))
	must(t, err)
	if n == 0 {
		t.Fatal("nothing purged")
	}
	if _, err := f.st.GetSession(ctx, old.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("expired session survived")
	}
	if _, err := f.st.GetSession(ctx, keep.ID); err != nil {
		t.Fatal("live session was purged")
	}
}

// testHostileInput stores classic injection payloads and reads them back
// byte for byte, proving values are bound and never interpreted as SQL.
func testHostileInput(t *testing.T, f fixture) {
	tn := f.tenant("acme")
	for i, payload := range []string{
		`'; DROP TABLE users; --`, `" OR "1"="1`, `x' OR '1'='1`, `\'; SELECT pg_sleep(5); --`, "Robert'); DROP TABLE tenants;--", `%_\`,
	} {
		email := fmt.Sprintf("u%d@example.com", i)
		u := f.user(tn.ID, email)
		u.Name = payload
		must(t, f.st.UpdateUser(ctx, u))
		got, err := f.st.GetUserByEmail(ctx, tn.ID, email)
		must(t, err)
		if got.Name != payload {
			t.Fatalf("payload not round-tripped: %q != %q", got.Name, payload)
		}
		if _, err := f.st.GetUserByEmail(ctx, tn.ID, payload); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("lookup by payload %q returned %v", payload, err)
		}
		if _, _, err := f.st.ListUsers(ctx, tn.ID, store.UserFilter{Email: payload, Status: payload}, store.Page{Limit: 5}); err != nil {
			t.Fatalf("filter with payload %q failed: %v", payload, err)
		}
	}
	if _, total, _ := f.st.ListUsers(ctx, tn.ID, store.UserFilter{}, store.Page{Limit: 100}); total != 6 {
		t.Fatalf("users table damaged: total=%d", total)
	}
}
