package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

func authParams(clientID string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"xyz-state"}, "code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}, "scope": {"profile"}}
}

// authBody is the JSON an application sends: the
// authorization request together with the user's credentials.
func authBody(clientID, email, pw string) M {
	m := M{"email": email, "password": pw}
	for k, v := range authParams(clientID) {
		m[k] = v[0]
	}
	return m
}

// authorize posts body to the authorization endpoint as an application does.
func (h *harness) authorize(body M, headers ...string) response {
	h.t.Helper()
	return h.do("POST", "/api/v1/oauth/authorize", "", body, headers...)
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

// signIn obtains an authorization code for ada.
func signIn(t *testing.T, h *harness, clientID string) string {
	t.Helper()
	code := h.expect(h.authorize(authBody(clientID, "ada@example.com", password)), 200, "").get(t, "code")
	if code == "" {
		t.Fatal("authorization succeeded without a code")
	}
	return code
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	h, tenantID, clientID := pkceSetup(t)

	az := h.expect(h.authorize(authBody(clientID, "ada@example.com", password)), 200, "")
	var out struct {
		Code, State, Iss        string
		RedirectURI, RedirectTo string
		ExpiresIn               int `json:"expires_in"`
	}
	json.Unmarshal(az.Body.Data, &out)
	out.RedirectURI, out.RedirectTo = az.get(t, "redirect_uri"), az.get(t, "redirect_to")
	if !strings.HasPrefix(out.Code, "kyc_") || out.State != "xyz-state" || out.Iss != "https://id.test" ||
		out.RedirectURI != redirectURI || out.ExpiresIn != 60 {
		t.Fatalf("authorization response: %s", az.Raw)
	}
	// redirect_to is the complete RFC 6749 authorization response, ready to navigate to.
	to, err := url.Parse(out.RedirectTo)
	if err != nil || to.Scheme+"://"+to.Host+to.Path != redirectURI || to.Query().Get("code") != out.Code ||
		to.Query().Get("state") != "xyz-state" || to.Query().Get("iss") != "https://id.test" {
		t.Fatalf("redirect_to: %q", out.RedirectTo)
	}
	// API only: JSON only, never cached, and no cookie that could become an ambient credential.
	if ct := az.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q", ct)
	}
	if az.Header.Get("Set-Cookie") != "" || az.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("authorization response headers: %v", az.Header)
	}

	status, tok := h.token(exchange(clientID, out.Code), "")
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
	noPKCE := authBody(confID, "ada@example.com", password)
	delete(noPKCE, "code_challenge")
	h.expect(h.authorize(noPKCE), 400, "invalid_request")

	// Another tenant's application cannot redeem it either.
	_, foreign := h.tenant("beta")
	fid, _, _ := strings.Cut(foreign, ":")
	code = signIn(t, h, spa)
	if status, _ := h.token(exchange(fid, code), foreign); status != 400 {
		t.Fatalf("cross-tenant redemption: %d", status)
	}
}

func TestNoBrowserInterface(t *testing.T) {
	h, _, clientID := pkceSetup(t)

	// The authorization endpoint is a JSON API: a browser navigating to it gets
	// neither a page nor a redirect.
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Get(h.srv.URL + "/api/v1/oauth/authorize?" + authParams(clientID).Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Location") != "" ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") || !strings.Contains(string(raw), `"method_not_allowed"`) {
		t.Fatalf("GET authorize: %d %v %s", res.StatusCode, res.Header, raw)
	}

	// No endpoint serves markup or sets a cookie, whatever the browser asks for.
	for _, path := range []string{"/", "/login", "/signin", "/api/v1/oauth/authorize", "/api/v1/oauth/token", "/authorize", "/.well-known/openid-configuration"} {
		req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
		req.Header.Set("Accept", "text/html")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if strings.Contains(res.Header.Get("Content-Type"), "html") || strings.Contains(strings.ToLower(string(body)), "<html") ||
			strings.Contains(string(body), "<form") || res.Header.Get("Set-Cookie") != "" || res.Header.Get("Location") != "" {
			t.Errorf("%s: served a browser interface: %d %v %.80s", path, res.StatusCode, res.Header, body)
		}
	}

	// There is no setting for a sign-in page: unknown fields are refused.
	tenantID, _ := h.tenant("other")
	h.expect(h.do("POST", "/api/v1/tenants/"+tenantID+"/applications", adminKey,
		M{"name": "x", "login_url": "https://app.example.com/sign-in"}), 400, "invalid_json")
}

func TestAuthorizeRequestValidation(t *testing.T) {
	h, _, clientID := pkceSetup(t)
	for name, tc := range map[string]struct {
		mod    func(M)
		status int
		want   string
	}{
		"unknown client":             {func(m M) { m["client_id"] = "app_nope" }, 400, "invalid_client"},
		"missing client":             {func(m M) { delete(m, "client_id") }, 400, "invalid_client"},
		"unregistered redirect":      {func(m M) { m["redirect_uri"] = "https://evil.example/cb" }, 400, "invalid_redirect_uri"},
		"redirect with extra query":  {func(m M) { m["redirect_uri"] = redirectURI + "?next=https://evil.example" }, 400, "invalid_redirect_uri"},
		"redirect differing by case": {func(m M) { m["redirect_uri"] = strings.ToUpper(redirectURI) }, 400, "invalid_redirect_uri"},
		"missing redirect":           {func(m M) { delete(m, "redirect_uri") }, 400, "invalid_redirect_uri"},
		"implicit flow":              {func(m M) { m["response_type"] = "token" }, 400, "unsupported_response_type"},
		"no challenge":               {func(m M) { delete(m, "code_challenge") }, 400, "invalid_request"},
		"plain method":               {func(m M) { m["code_challenge_method"] = "plain" }, 400, "invalid_request"},
		"no method":                  {func(m M) { delete(m, "code_challenge_method") }, 400, "invalid_request"},
		"malformed challenge":        {func(m M) { m["code_challenge"] = "too-short" }, 400, "invalid_request"},
		"oversized state":            {func(m M) { m["state"] = strings.Repeat("s", 600) }, 400, "invalid_request"},
		"unknown field":              {func(m M) { m["csrf_token"] = "x" }, 400, "invalid_json"},
		"response_type left out":     {func(m M) { delete(m, "response_type") }, 200, ""},
		"state and scope left out":   {func(m M) { delete(m, "state"); delete(m, "scope") }, 200, ""},
	} {
		body := authBody(clientID, "ada@example.com", password)
		tc.mod(body)
		if r := h.authorize(body); r.Status != tc.status || r.code() != tc.want {
			t.Errorf("%s: got %d %q, want %d %q (%s)", name, r.Status, r.code(), tc.status, tc.want, r.Raw)
		} else if tc.status != 200 && strings.Contains(r.Raw, "kyc_") {
			t.Errorf("%s: a rejected request still returned a code", name)
		}
	}
}

func TestAuthorizeDefences(t *testing.T) {
	h, _, clientID := pkceSetup(t)

	// A browser may only call from an origin registered on the application.
	h.expect(h.authorize(authBody(clientID, "ada@example.com", password), "Origin", "https://evil.example"), 403, "origin_not_allowed")
	ok := h.expect(h.authorize(authBody(clientID, "ada@example.com", password), "Origin", "https://app.example.com"), 200, "")
	if ok.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || ok.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("CORS headers for the application's own origin: %v", ok.Header)
	}

	// The endpoint only reads JSON, which an HTML form on another site cannot send.
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/oauth/authorize", strings.NewReader(url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "email": {"ada@example.com"}, "password": {password},
		"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || !strings.Contains(string(raw), "unsupported_media_type") || strings.Contains(string(raw), "kyc_") {
		t.Fatalf("form post: %d %s", res.StatusCode, raw)
	}

	// Wrong password and unknown user are indistinguishable, and nothing is echoed.
	wrong := h.expect(h.authorize(authBody(clientID, "ada@example.com", "wrong password")), 401, "invalid_credentials")
	unknown := h.expect(h.authorize(authBody(clientID, "nobody@example.com", "wrong password")), 401, "invalid_credentials")
	if wrong.Body.Error.Message != unknown.Body.Error.Message || strings.Contains(wrong.Raw, "wrong password") {
		t.Fatalf("wrong password vs unknown user: %s / %s", wrong.Raw, unknown.Raw)
	}
	// The authorization endpoint shares the account lockout with the login API (limit is 3 in tests).
	h.authorize(authBody(clientID, "ada@example.com", "wrong again"))
	h.authorize(authBody(clientID, "ada@example.com", "and again"))
	h.expect(h.authorize(authBody(clientID, "ada@example.com", password)), 423, "account_locked")
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
