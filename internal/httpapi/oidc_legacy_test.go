package httpapi_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rabbicse/keyora/guard"
	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/jwt"
)

func (h *harness) jwks() jwt.JWKS {
	res, err := http.Get(h.srv.URL + "/.well-known/jwks.json")
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var set jwt.JWKS
	json.NewDecoder(res.Body).Decode(&set)
	return set
}

func TestOpenIDConnect(t *testing.T) {
	h, _, clientID := pkceSetup(t)
	body := authBody(clientID, "ada@example.com", password)
	body["scope"], body["nonce"] = "openid email profile", "n-0S6_WzA2Mj"
	code := h.expect(h.authorize(body), 200, "").get(t, "code")
	status, tok := h.token(exchange(clientID, code), "")
	if status != 200 || tok["id_token"] == nil {
		t.Fatalf("token response without id_token: %d %v", status, tok)
	}
	idToken, access := tok["id_token"].(string), tok["access_token"].(string)

	id, err := jwt.Verify(idToken, h.jwks().KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: clientID, Now: h.env.Clock.Now})
	if err != nil {
		t.Fatalf("ID token does not verify: %v", err)
	}
	if id.Nonce != "n-0S6_WzA2Mj" || id.Email != "ada@example.com" || id.EmailVerified == nil || id.TokenUse != "id" ||
		id.AuthTime == 0 || id.Subject == "" || id.SessionID == "" {
		t.Fatalf("ID token claims: %+v", id)
	}
	if len(id.Roles) != 0 || len(id.Permissions) != 0 {
		t.Fatal("an ID token must not carry authorization data")
	}

	// An ID token is not an API credential, anywhere.
	h.expect(h.do("GET", "/api/v1/users/me", idToken, nil), 401, "invalid_token")
	g, _ := guard.New(guard.Config{Issuer: "https://id.test", Audience: clientID, JWKSURL: h.srv.URL + "/.well-known/jwks.json"})
	if _, err := g.Verify(t.Context(), idToken); err == nil {
		t.Fatal("guard accepted an ID token as an access token")
	}
	_ = access

	req, _ := http.NewRequest("GET", h.srv.URL+"/api/v1/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	json.NewDecoder(res.Body).Decode(&info)
	res.Body.Close()
	if res.StatusCode != 200 || info["sub"] != id.Subject || info["email"] != "ada@example.com" {
		t.Fatalf("userinfo: %d %v", res.StatusCode, info)
	}
	if _, enveloped := info["data"]; enveloped {
		t.Fatal("userinfo must be plain JSON")
	}
	h.expect(h.do("GET", "/api/v1/oauth/userinfo", idToken, nil), 401, "invalid_token")
	h.expect(h.do("GET", "/api/v1/oauth/userinfo", "", nil), 401, "unauthenticated")

	// Scopes control the claims: openid alone gives identity only.
	body["scope"] = "openid"
	_, tok = h.token(exchange(clientID, h.expect(h.authorize(body), 200, "").get(t, "code")), "")
	id, _ = jwt.Verify(tok["id_token"].(string), h.jwks().KeyFunc(), jwt.Validation{Now: h.env.Clock.Now})
	if id.Email != "" || id.Name != "" || id.EmailVerified != nil {
		t.Fatalf("claims released without their scope: %+v", id)
	}
	// No openid scope, no ID token.
	_, tok = h.token(exchange(clientID, signIn(t, h, clientID)), "")
	if tok["id_token"] != nil {
		t.Fatal("ID token issued without the openid scope")
	}

	res, _ = http.Get(h.srv.URL + "/.well-known/openid-configuration")
	var d map[string]any
	json.NewDecoder(res.Body).Decode(&d)
	res.Body.Close()
	if d["issuer"] != "https://id.test" || d["userinfo_endpoint"] != "https://id.test/api/v1/oauth/userinfo" ||
		d["jwks_uri"] != "https://id.test/.well-known/jwks.json" {
		t.Fatalf("discovery: %v", d)
	}
	if types, _ := json.Marshal(d["response_types_supported"]); string(types) != `["code"]` {
		t.Fatalf("discovery advertises flows that are not implemented: %s", types)
	}
}

// ---- tutorial-compatibility API ----

type legacyClient struct {
	t        *testing.T
	h        *harness
	clientID string
	secret   string
}

func legacySetup(t *testing.T) *legacyClient {
	var h *harness
	h = newHarness(t, func(c *httpapi.Config) { c.LegacyClientID = "pending" })
	// The legacy client ID is only known after the application exists, so
	// build a second server on the same service with it configured.
	tid, creds := h.tenant("acme")
	id, secret, _ := strings.Cut(creds, ":")
	apps := h.do("GET", "/api/v1/tenants/"+tid+"/applications", adminKey, nil)
	var list []struct{ ID string }
	json.Unmarshal(apps.Body.Data, &list)
	h.expect(h.do("PATCH", "/api/v1/tenants/"+tid+"/applications/"+list[0].ID, adminKey,
		M{"redirect_uris": []string{"http://localhost:3000/callback"}}), 200, "")
	h2 := &harness{t: t, env: h.env}
	h2.srv = newServer(t, h.env, func(c *httpapi.Config) { c.LegacyClientID = id })
	return &legacyClient{t: t, h: h2, clientID: id, secret: secret}
}

func (c *legacyClient) post(path string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	res, err := http.Post(c.h.srv.URL+path, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

var b64url = base64.RawURLEncoding

// login runs challenge + verify with the given verifier and returns the status and login token.
func (c *legacyClient) login(username string, verifier []byte) (int, string) {
	status, ch := c.post("/login/challenge", M{"username": username})
	if status != 200 {
		c.t.Fatalf("challenge: %d %v", status, ch)
	}
	challenge, _ := b64url.DecodeString(ch["challenge"].(string))
	mac := hmac.New(sha256.New, verifier)
	mac.Write(challenge)
	status, out := c.post("/login/verify", M{"username": username, "challenge_id": ch["challenge_id"], "proof": b64url.EncodeToString(mac.Sum(nil))})
	token, _ := out["login_token"].(string)
	return status, token
}

func (c *legacyClient) authorize(loginToken, state string) *http.Response {
	q := url.Values{"response_type": {"code"}, "client_id": {c.clientID}, "redirect_uri": {"http://localhost:3000/callback"},
		"scope": {"openid profile email"}, "state": {state}}
	req, _ := http.NewRequest("GET", c.h.srv.URL+"/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+loginToken)
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res
}

func (c *legacyClient) token(form url.Values) (int, map[string]any) {
	res, err := http.PostForm(c.h.srv.URL+"/token", form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestTutorialCompatibilityFlow(t *testing.T) {
	c := legacySetup(t)
	salt, verifier := []byte("0123456789abcdef"), []byte("argon2id-derived-verifier-32byte")

	if res, _ := http.Get(c.h.srv.URL + "/health"); res.StatusCode != 200 {
		t.Fatalf("/health: %d", res.StatusCode)
	}
	status, reg := c.post("/users/register", M{"username": "ada", "email": "ada@example.com",
		"salt": b64url.EncodeToString(salt), "verifier": b64url.EncodeToString(verifier)})
	if status != 201 || reg["username"] != "ada" || reg["id"] == nil {
		t.Fatalf("register: %d %v", status, reg)
	}
	if status, dup := c.post("/users/register", M{"username": "ada", "email": "other@example.com",
		"salt": b64url.EncodeToString(salt), "verifier": b64url.EncodeToString(verifier)}); status != 409 || dup["error"] == nil {
		t.Fatalf("duplicate username: %d %v", status, dup)
	}

	_, ch := c.post("/login/challenge", M{"username": "ada"})
	if ch["salt"] != b64url.EncodeToString(salt) {
		t.Fatalf("challenge did not return the registered salt: %v", ch)
	}
	status, loginToken := c.login("ada", verifier)
	if status != 200 || loginToken == "" {
		t.Fatalf("login: %d", status)
	}

	res := c.authorize(loginToken, "st&te=1")
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Host != "localhost:3000" || loc.Query().Get("state") != "st&te=1" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	code := loc.Query().Get("code")
	// The login token is single use (the tutorial let it be replayed for two minutes).
	if res := c.authorize(loginToken, "x"); res.StatusCode != 401 {
		t.Fatalf("login token replay: %d", res.StatusCode)
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:3000/callback"},
		"client_id": {c.clientID}, "client_secret": {c.secret}}
	status, tok := c.token(form)
	if status != 200 || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || tok["scope"] != "openid profile email" || tok["id_token"] == "" {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims, err := jwt.Verify(tok["access_token"].(string), c.h.jwks().KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: c.clientID, Now: c.h.env.Clock.Now})
	if err != nil || claims.Subject != reg["id"] {
		t.Fatalf("access token: %v %+v", err, claims)
	}
	if status, again := c.token(form); status != 400 {
		t.Fatalf("code replay: %d %v", status, again)
	}

	// Refresh, the tutorial way: just the refresh token.
	status, next := c.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}})
	if status == 200 {
		t.Fatal("the session should have been revoked by the code replay above")
	}
	_, loginToken = c.login("ada", verifier)
	loc, _ = url.Parse(c.authorize(loginToken, "s").Header.Get("Location"))
	form.Set("code", loc.Query().Get("code"))
	_, tok = c.token(form)
	status, next = c.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}})
	if status != 200 || next["access_token"] == nil || next["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh: %d %v", status, next)
	}

	// Introspection with real application credentials.
	req, _ := http.NewRequest("POST", c.h.srv.URL+"/oauth/introspect", strings.NewReader(`{"token":"`+next["access_token"].(string)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.clientID, c.secret)
	ires, _ := http.DefaultClient.Do(req)
	var in map[string]any
	json.NewDecoder(ires.Body).Decode(&in)
	ires.Body.Close()
	if in["active"] != true || in["sub"] != reg["id"] {
		t.Fatalf("introspect: %v", in)
	}
	req, _ = http.NewRequest("POST", c.h.srv.URL+"/oauth/introspect", strings.NewReader(`{"token":"x"}`))
	req.SetBasicAuth("resource-server", "secret") // the tutorial's hard-coded pair must not work
	if ires, _ = http.DefaultClient.Do(req); ires.StatusCode != 401 {
		t.Fatalf("hard-coded tutorial credentials accepted: %d", ires.StatusCode)
	}
}

func TestTutorialCompatibilityHardening(t *testing.T) {
	c := legacySetup(t)
	verifier := []byte("argon2id-derived-verifier-32byte")
	c.post("/users/register", M{"username": "ada", "email": "ada@example.com",
		"salt": b64url.EncodeToString([]byte("0123456789abcdef")), "verifier": b64url.EncodeToString(verifier)})

	// Unknown users are not revealed: same status and shape, stable fake salt.
	s1, a := c.post("/login/challenge", M{"username": "ghost"})
	_, b := c.post("/login/challenge", M{"username": "ghost"})
	if s1 != 200 || a["salt"] == nil || a["salt"] != b["salt"] || a["challenge"] == b["challenge"] {
		t.Fatalf("unknown user is distinguishable: %d %v %v", s1, a, b)
	}
	if status, _ := c.login("ghost", verifier); status != 401 {
		t.Fatalf("unknown user logged in: %d", status)
	}

	// A challenge is good for one attempt, and only for its own user.
	_, ch := c.post("/login/challenge", M{"username": "ada"})
	challenge, _ := b64url.DecodeString(ch["challenge"].(string))
	mac := hmac.New(sha256.New, verifier)
	mac.Write(challenge)
	proof := b64url.EncodeToString(mac.Sum(nil))
	if status, _ := c.post("/login/verify", M{"username": "ada", "challenge_id": ch["challenge_id"], "proof": "AAAA"}); status != 401 {
		t.Fatalf("bad proof: %d", status)
	}
	if status, _ := c.post("/login/verify", M{"username": "ada", "challenge_id": ch["challenge_id"], "proof": proof}); status != 401 {
		t.Fatal("a challenge could be answered twice")
	}

	// Repeated failures lock the account (limit is 3 in tests), even for the right verifier.
	c.login("ada", []byte("wrong-verifier-wrong-verifier-00"))
	c.login("ada", []byte("wrong-verifier-wrong-verifier-00"))
	if status, _ := c.login("ada", verifier); status != 401 {
		t.Fatalf("lockout not applied to the legacy login: %d", status)
	}

	// A legacy account has no password, so the modern login refuses it...
	h := c.h
	for _, pw := range []string{"", "anything at all", string(verifier)} {
		if r := h.do("POST", "/api/v1/auth/login", c.clientID+":"+c.secret, M{"email": "ada@example.com", "password": pw}); r.Status == 200 {
			t.Fatalf("a legacy account without a password signed in through the password login with %q", pw)
		}
	}
	// ...until its owner sets one through password reset, which is the migration path.
	h.expect(h.do("POST", "/api/v1/auth/password/forgot", c.clientID+":"+c.secret, M{"email": "ada@example.com"}), 202, "")
	msg, _ := h.env.Mail.Last("ada@example.com")
	reset := strings.Fields(msg.Body[strings.Index(msg.Body, "kyp_"):])[0]
	h.expect(h.do("POST", "/api/v1/auth/password/reset", "", M{"token": reset, "new_password": "a brand new password"}), 204, "")
	h.expect(h.do("POST", "/api/v1/auth/login", c.clientID+":"+c.secret, M{"email": "ada@example.com", "password": "a brand new password"}), 200, "")

	// Codes from the two flows are not interchangeable.
	_, loginToken := c.login("ada", verifier) // the reset cleared the lock
	loc, _ := url.Parse(c.authorize(loginToken, "s").Header.Get("Location"))
	legacyCode := loc.Query().Get("code")
	if legacyCode == "" {
		t.Fatal("no legacy code issued")
	}
	if status, body := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {legacyCode},
		"redirect_uri": {"http://localhost:3000/callback"}, "code_verifier": {verifier43}}, c.clientID+":"+c.secret); status != 400 {
		t.Fatalf("a PKCE-less legacy code was redeemed at the standard token endpoint: %d %v", status, body)
	}
	// Legacy token endpoint requires the client secret.
	_, loginToken = c.login("ada", verifier)
	loc, _ = url.Parse(c.authorize(loginToken, "s").Header.Get("Location"))
	if status, _ := c.token(url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://localhost:3000/callback"}, "client_id": {c.clientID}, "client_secret": {"wrong"}}); status != 400 {
		t.Fatalf("legacy token issued without the client secret: %d", status)
	}
	if res := c.authorize("made-up-token", "s"); res.StatusCode != 401 {
		t.Fatalf("forged login token: %d", res.StatusCode)
	}
	// Bad registration input.
	for _, body := range []M{
		{"username": "x", "email": "x@example.com", "salt": "AAAAAAAAAAAA", "verifier": b64url.EncodeToString(verifier)},
		{"username": "bob", "email": "nope", "salt": "AAAAAAAAAAAA", "verifier": b64url.EncodeToString(verifier)},
		{"username": "bob", "email": "bob@example.com", "salt": "!!", "verifier": b64url.EncodeToString(verifier)},
		{"username": "bob", "email": "bob@example.com", "salt": "AAAAAAAAAAAA", "verifier": "AA"},
	} {
		if status, _ := c.post("/users/register", body); status != 400 {
			t.Fatalf("invalid registration accepted: %d %v", status, body)
		}
	}
}

func TestTutorialAPIIsOffByDefault(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/users/register", "/login/challenge", "/login/verify", "/token", "/oauth/introspect"} {
		h.expect(h.do("POST", p, "", M{}), 404, "route_not_found")
	}
	h.expect(h.do("GET", "/authorize", "", nil), 404, "route_not_found")
	h.expect(h.do("GET", "/health", "", nil), 404, "route_not_found")
}
