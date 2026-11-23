package guard

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

// fakeKeyora serves a JWKS and counts how often it is fetched.
type fakeKeyora struct {
	srv     *httptest.Server
	fetches atomic.Int64
	set     atomic.Pointer[jwt.JWKS]
	down    atomic.Bool
}

func newFakeKeyora(t *testing.T) *fakeKeyora {
	f := &fakeKeyora{}
	f.set.Store(&jwt.JWKS{})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(f.set.Load())
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKeyora) addKey(t *testing.T, kid string) jwt.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := jwt.JWKS{Keys: append(append([]jwt.JWK{}, f.set.Load().Keys...), jwt.PublicJWK(kid, &k.PublicKey))}
	f.set.Store(&set)
	return jwt.Signer{Key: k, KeyID: kid}
}

func (f *fakeKeyora) token(t *testing.T, s jwt.Signer, mod func(*jwt.Claims)) string {
	c := jwt.Claims{Issuer: f.srv.URL, Subject: "user-1", Audience: jwt.Audience{"app-1"}, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Roles: []string{"editor"}, Permissions: []string{"orders:read"}}
	if mod != nil {
		mod(&c)
	}
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func call(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMiddleware(t *testing.T) {
	f := newFakeKeyora(t)
	signer := f.addKey(t, "k1")
	g, err := New(Config{Issuer: f.srv.URL + "/", Audience: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ClaimsFromContext(r.Context())
		w.Write([]byte(c.Subject))
	})
	protected := g.Middleware(ok)

	if rec := call(protected, f.token(t, signer, nil)); rec.Code != 200 || rec.Body.String() != "user-1" {
		t.Fatalf("valid token: %d %s", rec.Code, rec.Body)
	}
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]struct {
		token string
		code  string
	}{
		"missing":        {"", "missing_token"},
		"garbage":        {"abc", "invalid_token"},
		"expired":        {f.token(t, signer, func(c *jwt.Claims) { c.ExpiresAt = time.Now().Add(-time.Minute).Unix() }), "token_expired"},
		"other audience": {f.token(t, signer, func(c *jwt.Claims) { c.Audience = jwt.Audience{"app-2"} }), "invalid_token"},
		"other issuer":   {f.token(t, signer, func(c *jwt.Claims) { c.Issuer = "https://evil.test" }), "invalid_token"},
		"forged key":     {f.token(t, jwt.Signer{Key: stranger, KeyID: "k1"}, nil), "invalid_token"},
	}
	for name, tc := range cases {
		rec := call(protected, tc.token)
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}

	tok := f.token(t, signer, nil)
	for name, tc := range map[string]struct {
		mw   func(http.Handler) http.Handler
		want int
	}{
		"has permission":      {RequirePermission("orders:read"), 200},
		"lacks permission":    {RequirePermission("orders:write"), 403},
		"needs all listed":    {RequirePermission("orders:read", "orders:write"), 403},
		"has one of roles":    {RequireRole("admin", "editor"), 200},
		"has none of roles":   {RequireRole("admin"), 403},
		"no permission named": {RequirePermission(), 200},
	} {
		if rec := call(g.Middleware(tc.mw(ok)), tok); rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", name, rec.Code, tc.want)
		}
	}
	// Used without Middleware, the checks fail closed.
	if rec := call(RequirePermission("orders:read")(ok), tok); rec.Code != 401 {
		t.Fatalf("authorization without authentication returned %d", rec.Code)
	}
}

func TestKeyCachingRotationAndOutage(t *testing.T) {
	f := newFakeKeyora(t)
	k1 := f.addKey(t, "k1")
	g, _ := New(Config{Issuer: f.srv.URL, Audience: "app-1"})
	clock := time.Now()
	g.now = func() time.Time { return clock }
	verify := func(tok string) error { _, err := g.Verify(t.Context(), tok); return err }

	for i := 0; i < 50; i++ {
		if err := verify(f.token(t, k1, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.fetches.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times for 50 verifications, want 1", n)
	}

	// Tokens naming unknown keys must not turn into a fetch per request.
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	for i := 0; i < 50; i++ {
		if verify(f.token(t, jwt.Signer{Key: stranger, KeyID: "made-up"}, nil)) == nil {
			t.Fatal("token with unknown key accepted")
		}
	}
	if n := f.fetches.Load(); n != 1 {
		t.Fatalf("unknown key IDs caused %d fetches inside the refetch window", n)
	}

	// Rotation: a new key is picked up as soon as the refetch window allows.
	k2 := f.addKey(t, "k2")
	clock = clock.Add(minRefetch + time.Second)
	if err := verify(f.token(t, k2, nil)); err != nil {
		t.Fatalf("token signed with a rotated key rejected: %v", err)
	}
	if err := verify(f.token(t, k1, nil)); err != nil {
		t.Fatalf("old key stopped working after rotation: %v", err)
	}

	// Keyora outage after the cache expires: keep verifying with known keys.
	f.down.Store(true)
	clock = clock.Add(10 * time.Minute)
	if err := verify(f.token(t, k2, func(c *jwt.Claims) { c.ExpiresAt = clock.Add(time.Hour).Unix() })); err != nil {
		t.Fatalf("verification failed during a Keyora outage despite cached keys: %v", err)
	}

	cold, _ := New(Config{Issuer: f.srv.URL, Audience: "app-1"})
	if _, err := cold.Verify(t.Context(), f.token(t, k2, nil)); err == nil {
		t.Fatal("token accepted with no keys available")
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{Issuer: "https://id.test"}); err == nil {
		t.Fatal("guard created without an audience")
	}
	if _, err := New(Config{Audience: "app"}); err == nil {
		t.Fatal("guard created without an issuer")
	}
	for header, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "Bearer ": "", "abc": ""} {
		if got, _ := BearerToken(header); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}
