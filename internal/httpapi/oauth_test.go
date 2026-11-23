package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

const (
	redirectURI = "https://app.example.com/callback"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

var verifier43 = strings.Repeat("v", 43)

func challengeFor(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// browser is a cookie-keeping client that does not follow redirects, like a
// user agent whose navigation we want to inspect.
type browser struct {
	t *testing.T
	h *harness
	c *http.Client
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: h.t, h: h, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type page struct {
	Status   int
	Body     string
	Location *url.URL
	Header   http.Header
}

func (b *browser) finish(res *http.Response, err error) page {
	b.t.Helper()
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	p := page{Status: res.StatusCode, Body: string(raw), Header: res.Header}
	if loc := res.Header.Get("Location"); loc != "" {
		p.Location, _ = url.Parse(loc)
	}
	return p
}

func (b *browser) open(params url.Values) page {
	return b.finish(b.c.Get(b.h.srv.URL + "/api/v1/oauth/authorize?" + params.Encode()))
}

var hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// submit fills in the sign-in form exactly as rendered and posts it.
func (b *browser) submit(form page, email, pw string) page {
	b.t.Helper()
	fields := url.Values{"email": {email}, "password": {pw}}
	for _, m := range hiddenRe.FindAllStringSubmatch(form.Body, -1) {
		fields.Set(m[1], strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&lt;", "<", "&gt;", ">", "&#39;", "'", "&#43;", "+").Replace(m[2]))
	}
	if fields.Get("csrf_token") == "" {
		b.t.Fatalf("no sign-in form in page (status %d): %s", form.Status, form.Body)
	}
	return b.finish(b.c.PostForm(b.h.srv.URL+"/api/v1/oauth/authorize", fields))
}

func authParams(clientID string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"xyz-state"}, "code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}, "scope": {"profile"}}
}

func (h *harness) token(form url.Values, basic string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id, secret, ok := strings.Cut(basic, ":"); ok {
		req.SetBasicAuth(id, secret)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func exchange(clientID, code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}}
}

// pkceSetup creates a tenant with a public SPA and a registered user.
func pkceSetup(t *testing.T) (h *harness, tenantID, clientID string) {
	h = newHarness(t, nil)
	tenantID, backend := h.tenant("acme")
	spa := h.expect(h.do("POST", "/api/v1/tenants/"+tenantID+"/applications", adminKey,
		M{"name": "Acme <SPA>", "type": "public", "redirect_uris": []string{redirectURI}, "allowed_origins": []string{"https://app.example.com"}}), 201, "")
	h.expect(h.do("POST", "/api/v1/auth/register", backend, M{"email": "ada@example.com", "password": password}), 201, "")
	return h, tenantID, spa.get(t, "client_id")
}

// signIn runs the browser half of the flow and returns the authorization code.
func signIn(t *testing.T, h *harness, clientID string) string {
	t.Helper()
	b := h.browser()
	done := b.submit(b.open(authParams(clientID)), "ada@example.com", password)
	if done.Status != http.StatusSeeOther || done.Location == nil || done.Location.Query().Get("code") == "" {
		t.Fatalf("sign-in did not redirect with a code: %d %v %s", done.Status, done.Location, done.Body)
	}
	return done.Location.Query().Get("code")
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	h, tenantID, clientID := pkceSetup(t)
	b := h.browser()

	form := b.open(authParams(clientID))
	if form.Status != 200 || !strings.Contains(form.Body, `name="password"`) || !strings.Contains(form.Body, "Acme &lt;SPA&gt;") {
		t.Fatalf("sign-in page: %d %s", form.Status, form.Body)
	}
	csp := form.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") ||
		form.Header.Get("X-Frame-Options") != "DENY" || form.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("sign-in page headers are too weak: %v", form.Header)
	}
	if c := form.Header.Get("Set-Cookie"); !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") {
		t.Fatalf("CSRF cookie attributes: %q", c)
	}

	done := b.submit(form, "ada@example.com", password)
	if done.Status != http.StatusSeeOther {
		t.Fatalf("status %d: %s", done.Status, done.Body)
	}
	q := done.Location.Query()
	if done.Location.Scheme+"://"+done.Location.Host+done.Location.Path != redirectURI || q.Get("state") != "xyz-state" ||
		q.Get("iss") != "https://id.test" || !strings.HasPrefix(q.Get("code"), "kyc_") {
		t.Fatalf("redirect: %s", done.Location)
	}

	status, tok := h.token(exchange(clientID, q.Get("code")), "")
	if status != 200 || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || tok["scope"] != "profile" {
		t.Fatalf("token response: %d %v", status, tok)
	}
	if _, enveloped := tok["data"]; enveloped {
		t.Fatal("token endpoint must use the RFC 6749 format")
	}
	access := tok["access_token"].(string)
	res, _ := http.Get(h.srv.URL + "/.well-known/jwks.json")
	var set jwt.JWKS
	json.NewDecoder(res.Body).Decode(&set)
	res.Body.Close()
	claims, err := jwt.Verify(access, set.KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: clientID, Now: h.env.Clock.Now})
	if err != nil || claims.Email != "ada@example.com" || claims.TenantID != tenantID {
		t.Fatalf("access token: %v %+v", err, claims)
	}
	h.expect(h.do("GET", "/api/v1/users/me", access, nil), 200, "")

	// The refresh grant works for a public client, rotates, and detects reuse.
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}}
	status, next := h.token(refresh, "")
	if status != 200 || next["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh grant: %d %v", status, next)
	}
	if status, body := h.token(refresh, ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh replay: %d %v", status, body)
	}

	audit := h.do("GET", "/api/v1/tenants/"+tenantID+"/audit-events?type=token.code_exchanged", adminKey, nil)
	if audit.Body.Meta.Pagination.Total != 1 {
		t.Fatalf("code exchange was not audited: %s", audit.Raw)
	}
}

func TestPKCEVerifierIsEnforced(t *testing.T) {
	h, _, clientID := pkceSetup(t)
	bad := func(name string, mod func(url.Values)) {
		t.Helper()
		code := signIn(t, h, clientID)
		form := exchange(clientID, code)
		mod(form)
		if status, body := h.token(form, ""); status != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("%s: got %d %v, want 400 invalid_grant", name, status, body)
		}
		// A failed attempt burns the code: the right verifier does not get a second chance.
		if status, body := h.token(exchange(clientID, code), ""); status != 400 {
			t.Fatalf("%s: code still redeemable after a failed attempt: %d %v", name, status, body)
		}
	}
	bad("wrong verifier", func(f url.Values) { f.Set("code_verifier", strings.Repeat("a", 43)) })
	bad("missing verifier", func(f url.Values) { f.Del("code_verifier") })
	bad("verifier too short", func(f url.Values) { f.Set("code_verifier", "short") })
	bad("the challenge sent as the verifier", func(f url.Values) { f.Set("code_verifier", challengeFor(verifier)) })
	bad("different redirect_uri", func(f url.Values) { f.Set("redirect_uri", redirectURI+"/other") })
	bad("missing redirect_uri", func(f url.Values) { f.Del("redirect_uri") })

	for _, code := range []string{"", "kyc_never-issued", strings.Repeat("x", 5000)} {
		if status, body := h.token(exchange(clientID, code), ""); status != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("code %.20q: %d %v", code, status, body)
		}
	}
}

func TestAuthorizationCodeIsSingleUseAndShortLived(t *testing.T) {
	h, tenantID, clientID := pkceSetup(t)

	code := signIn(t, h, clientID)
	status, tok := h.token(exchange(clientID, code), "")
	if status != 200 {
		t.Fatalf("first exchange: %d %v", status, tok)
	}
	// Replay: refused, and the tokens already issued from the code are revoked.
	if status, body := h.token(exchange(clientID, code), ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", status, body)
	}
	h.expect(h.do("GET", "/api/v1/users/me", tok["access_token"].(string), nil), 401, "invalid_token")
	if r := h.do("GET", "/api/v1/tenants/"+tenantID+"/audit-events?type=code.reuse_detected", adminKey, nil); r.Body.Meta.Pagination.Total != 1 {
		t.Fatalf("code reuse was not audited: %s", r.Raw)
	}

	code = signIn(t, h, clientID)
	h.env.Clock.Advance(61 * time.Second)
	if status, body := h.token(exchange(clientID, code), ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("expired code: %d %v", status, body)
	}

	// Concurrent redemption: exactly one request gets tokens.
	code = signIn(t, h, clientID)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := h.token(exchange(clientID, code), ""); status == 200 {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins > 1 {
		t.Fatalf("%d concurrent requests redeemed one code", wins)
	}
}

func TestAuthorizationCodeIsBoundToItsClient(t *testing.T) {
	h, tenantID, spa := pkceSetup(t)
	conf := h.expect(h.do("POST", "/api/v1/tenants/"+tenantID+"/applications", adminKey,
		M{"name": "server-app", "redirect_uris": []string{redirectURI}}), 201, "")
	confID, confSecret := conf.get(t, "client_id"), conf.get(t, "client_secret")

	// A code issued to the SPA cannot be redeemed by another application.
	code := signIn(t, h, spa)
	if status, body := h.token(exchange(confID, code), confID+":"+confSecret); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("cross-client redemption: %d %v", status, body)
	}

	// A confidential application must authenticate, and still needs PKCE.
	code = signIn(t, h, confID)
	if status, body := h.token(exchange(confID, code), ""); status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("confidential client without secret: %d %v", status, body)
	}
	if status, body := h.token(exchange(confID, code), confID+":"+confSecret); status != 200 {
		t.Fatalf("confidential client with secret: %d %v", status, body)
	}
	noPKCE := authParams(confID)
	noPKCE.Del("code_challenge")
	if p := h.browser().open(noPKCE); p.Status != http.StatusSeeOther || p.Location.Query().Get("error") != "invalid_request" {
		t.Fatalf("confidential client was allowed to skip PKCE: %d %s", p.Status, p.Body)
	}

	// Another tenant's application cannot redeem it either.
	_, foreign := h.tenant("beta")
	fid, _, _ := strings.Cut(foreign, ":")
	code = signIn(t, h, spa)
	if status, _ := h.token(exchange(fid, code), foreign); status != 400 {
		t.Fatalf("cross-tenant redemption: %d", status)
	}
}

func TestAuthorizeRequestValidation(t *testing.T) {
	h, _, clientID := pkceSetup(t)
	b := h.browser()

	// Untrusted redirect target: an error page on Keyora, never a redirect.
	for name, mod := range map[string]func(url.Values){
		"unknown client":             func(v url.Values) { v.Set("client_id", "app_nope") },
		"missing client":             func(v url.Values) { v.Del("client_id") },
		"unregistered redirect":      func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") },
		"redirect with extra path":   func(v url.Values) { v.Set("redirect_uri", redirectURI+"/../evil") },
		"redirect with extra query":  func(v url.Values) { v.Set("redirect_uri", redirectURI+"?next=https://evil.example") },
		"redirect differing by case": func(v url.Values) { v.Set("redirect_uri", strings.ToUpper(redirectURI)) },
		"missing redirect":           func(v url.Values) { v.Del("redirect_uri") },
	} {
		v := authParams(clientID)
		mod(v)
		if p := b.open(v); p.Status != 400 || p.Location != nil || strings.Contains(p.Body, `name="password"`) {
			t.Errorf("%s: got %d location=%v, want a 400 error page and no redirect", name, p.Status, p.Location)
		}
	}

	// Trusted redirect target: errors go back to the application.
	for name, tc := range map[string]struct {
		mod  func(url.Values)
		want string
	}{
		"implicit flow":       {func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		"no response_type":    {func(v url.Values) { v.Del("response_type") }, "unsupported_response_type"},
		"no challenge":        {func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		"plain method":        {func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no method":           {func(v url.Values) { v.Del("code_challenge_method") }, "invalid_request"},
		"malformed challenge": {func(v url.Values) { v.Set("code_challenge", "too-short") }, "invalid_request"},
		"oversized state":     {func(v url.Values) { v.Set("state", strings.Repeat("s", 600)) }, "invalid_request"},
	} {
		v := authParams(clientID)
		tc.mod(v)
		p := b.open(v)
		if p.Status != http.StatusSeeOther || p.Location == nil || p.Location.Query().Get("error") != tc.want ||
			p.Location.Host != "app.example.com" || p.Location.Query().Get("code") != "" {
			t.Errorf("%s: got %d %v, want a redirect with error=%s", name, p.Status, p.Location, tc.want)
		}
	}

	// Hostile parameter values are escaped in the page and survive the round trip intact.
	evil := `"><script>alert(1)</script>`
	v := authParams(clientID)
	v.Set("state", evil)
	form := b.open(v)
	if strings.Contains(form.Body, "<script>") {
		t.Fatal("state was reflected unescaped into the sign-in page")
	}
	if done := b.submit(form, "ada@example.com", password); done.Location == nil || done.Location.Query().Get("state") != evil {
		t.Fatalf("state was not returned unchanged: %v", done.Location)
	}
}

func TestSignInPageDefences(t *testing.T) {
	h, _, clientID := pkceSetup(t)

	// Login CSRF: a form posted without the cookie from Keyora's own page is refused.
	b := h.browser()
	form := b.open(authParams(clientID))
	if p := h.browser().submit(form, "ada@example.com", password); p.Status != http.StatusForbidden || p.Location != nil {
		t.Fatalf("cross-site form post was accepted: %d %v", p.Status, p.Location)
	}
	forged := form
	forged.Body = regexp.MustCompile(`name="csrf_token" value="[^"]*"`).ReplaceAllString(form.Body, `name="csrf_token" value="forged"`)
	if p := b.submit(forged, "ada@example.com", password); p.Status != http.StatusForbidden || p.Location != nil {
		t.Fatalf("forged CSRF token accepted: %d", p.Status)
	}

	// Wrong password: the page again, no redirect, no hint about which part was wrong.
	b = h.browser()
	wrong := b.submit(b.open(authParams(clientID)), "ada@example.com", "wrong password")
	unknown := b.submit(b.open(authParams(clientID)), "nobody@example.com", "wrong password")
	if wrong.Status != 401 || wrong.Location != nil || !strings.Contains(wrong.Body, "Incorrect email or password.") || strings.Contains(wrong.Body, "wrong password") {
		t.Fatalf("wrong password: %d %s", wrong.Status, wrong.Body)
	}
	if unknown.Status != 401 || !strings.Contains(unknown.Body, "Incorrect email or password.") {
		t.Fatalf("unknown user is distinguishable from a wrong password: %d", unknown.Status)
	}
	// The hosted page shares the account lockout with the API (limit is 3 in tests).
	b.submit(b.open(authParams(clientID)), "ada@example.com", "wrong again")
	b.submit(b.open(authParams(clientID)), "ada@example.com", "and again")
	if locked := b.submit(b.open(authParams(clientID)), "ada@example.com", password); locked.Status != http.StatusLocked || locked.Location != nil {
		t.Fatalf("lockout not enforced on the hosted page: %d", locked.Status)
	}
}

func TestOAuthMetadata(t *testing.T) {
	h := newHarness(t, nil)
	res, err := http.Get(h.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	json.NewDecoder(res.Body).Decode(&m)
	if m["issuer"] != "https://id.test" || m["authorization_endpoint"] != "https://id.test/api/v1/oauth/authorize" ||
		m["token_endpoint"] != "https://id.test/api/v1/oauth/token" || m["jwks_uri"] != "https://id.test/.well-known/jwks.json" {
		t.Fatalf("metadata: %v", m)
	}
	if methods, _ := json.Marshal(m["code_challenge_methods_supported"]); string(methods) != `["S256"]` {
		t.Fatalf("only S256 may be advertised, got %s", methods)
	}
	if _, oidc := m["id_token_signing_alg_values_supported"]; oidc {
		t.Fatal("metadata claims OpenID Connect support that does not exist")
	}
}
