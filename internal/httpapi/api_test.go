package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	"github.com/rabbicse/keyora/jwt"
)

const (
	adminKey = "test-admin-key-0123456789abcdef0123456789"
	password = "correct horse battery"
)

type harness struct {
	t   *testing.T
	env *testutil.Env
	srv *httptest.Server
}

func newHarness(t *testing.T, mod func(*httpapi.Config)) *harness {
	t.Helper()
	env := testutil.NewEnv(t, memory.New(), nil)
	cfg := httpapi.Config{AdminKey: adminKey, MetricsEnabled: true, Version: "test", OpenAPI: []byte("openapi: 3.0.3\n"),
		CORSAllowedOrigins: []string{"https://console.test"}}
	if mod != nil {
		mod(&cfg)
	}
	srv := httptest.NewServer(httpapi.New(env.Svc, cfg, testutil.Logger()))
	t.Cleanup(srv.Close)
	return &harness{t: t, env: env, srv: srv}
}

// newServer starts another API server on an existing service.
func newServer(t *testing.T, env *testutil.Env, mod func(*httpapi.Config)) *httptest.Server {
	t.Helper()
	cfg := httpapi.Config{AdminKey: adminKey, MetricsEnabled: true, Version: "test"}
	mod(&cfg)
	srv := httptest.NewServer(httpapi.New(env.Svc, cfg, testutil.Logger()))
	t.Cleanup(srv.Close)
	return srv
}

type response struct {
	Status int
	Header http.Header
	Raw    string
	Body   struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Details map[string]string `json:"details"`
		} `json:"error"`
		Meta struct {
			RequestID  string `json:"request_id"`
			Pagination *struct {
				Limit, Offset, Total int
			} `json:"pagination"`
		} `json:"meta"`
	}
}

func (r response) code() string {
	if r.Body.Error == nil {
		return ""
	}
	return r.Body.Error.Code
}

func (r response) get(t *testing.T, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body.Data, &m); err != nil {
		t.Fatalf("data is not an object: %s", r.Raw)
	}
	s, _ := m[key].(string)
	return s
}

// do sends a request. auth is a bearer token, or "id:secret" for HTTP Basic.
func (h *harness) do(method, path, auth string, body any, headers ...string) response {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id, secret, ok := strings.Cut(auth, ":"); ok {
		req.SetBasicAuth(id, secret)
	} else if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := response{Status: res.StatusCode, Header: res.Header, Raw: string(raw)}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func (h *harness) expect(r response, status int, code string) response {
	h.t.Helper()
	if r.Status != status || r.code() != code {
		h.t.Fatalf("got %d %q, want %d %q\nbody: %s", r.Status, r.code(), status, code, r.Raw)
	}
	return r
}

type M = map[string]any

// tenant creates a tenant with one confidential application and returns
// (tenantID, "client_id:client_secret").
func (h *harness) tenant(slug string) (string, string) {
	h.t.Helper()
	tn := h.expect(h.do("POST", "/api/v1/tenants", adminKey, M{"slug": slug, "name": slug}), 201, "")
	id := tn.get(h.t, "id")
	app := h.expect(h.do("POST", "/api/v1/tenants/"+id+"/applications", adminKey, M{"name": "web"}), 201, "")
	return id, app.get(h.t, "client_id") + ":" + app.get(h.t, "client_secret")
}

// user registers and signs in, returning (userID, accessToken, refreshToken).
func (h *harness) user(client, email string) (string, string, string) {
	h.t.Helper()
	u := h.expect(h.do("POST", "/api/v1/auth/register", client, M{"email": email, "password": password, "name": "Ada"}), 201, "")
	l := h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": email, "password": password}), 200, "")
	return u.get(h.t, "id"), l.get(h.t, "access_token"), l.get(h.t, "refresh_token")
}

func (h *harness) makeAdmin(tenantID, userID string) {
	h.t.Helper()
	roles := h.expect(h.do("GET", "/api/v1/tenants/"+tenantID+"/roles", adminKey, nil), 200, "")
	var list []struct{ ID, Name string }
	json.Unmarshal(roles.Body.Data, &list)
	h.expect(h.do("PUT", "/api/v1/tenants/"+tenantID+"/users/"+userID+"/roles/"+list[0].ID, adminKey, nil), 204, "")
}

func TestFullIntegrationFlow(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	base := "/api/v1/tenants/" + tid

	// RBAC setup through the management API.
	h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "orders:read", "description": "Read orders"}), 201, "")
	role := h.expect(h.do("POST", base+"/roles", adminKey, M{"name": "viewer", "permissions": []string{"orders:read"}}), 201, "")

	reg := h.expect(h.do("POST", "/api/v1/auth/register", client, M{"email": "ada@example.com", "password": password, "name": "Ada"}), 201, "")
	if strings.Contains(reg.Raw, "password") || strings.Contains(reg.Raw, "pbkdf2") {
		t.Fatalf("registration response leaks credential material: %s", reg.Raw)
	}
	uid := reg.get(t, "id")
	h.expect(h.do("PUT", base+"/users/"+uid+"/roles/"+role.get(t, "id"), adminKey, nil), 204, "")

	login := h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": password}), 200, "")
	access, refresh := login.get(t, "access_token"), login.get(t, "refresh_token")
	if login.get(t, "token_type") != "Bearer" || !strings.Contains(login.Raw, `"user":{"id":"`+uid) {
		t.Fatalf("unexpected login body: %s", login.Raw)
	}

	// A resource server verifies the token offline using the published JWKS.
	res, _ := http.Get(h.srv.URL + "/.well-known/jwks.json")
	var set jwt.JWKS
	json.NewDecoder(res.Body).Decode(&set)
	res.Body.Close()
	clientID, _, _ := strings.Cut(client, ":")
	claims, err := jwt.Verify(access, set.KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: clientID, Now: h.env.Clock.Now})
	if err != nil {
		t.Fatalf("access token does not verify against the JWKS endpoint: %v", err)
	}
	if !claims.HasRole("viewer") || !claims.HasPermission("orders:read") || claims.TenantID != tid {
		t.Fatalf("claims: %+v", claims)
	}
	if res.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatal("JWKS should be cacheable")
	}

	me := h.expect(h.do("GET", "/api/v1/users/me", access, nil), 200, "")
	if !strings.Contains(me.Raw, `"permissions":["orders:read"]`) || !strings.Contains(me.Raw, `"roles":["viewer"]`) {
		t.Fatalf("profile: %s", me.Raw)
	}
	h.expect(h.do("PATCH", "/api/v1/users/me", access, M{"name": "Ada L."}), 200, "")
	sessions := h.expect(h.do("GET", "/api/v1/users/me/sessions", access, nil), 200, "")
	if sessions.Body.Meta.Pagination == nil || sessions.Body.Meta.Pagination.Total != 1 {
		t.Fatalf("sessions: %s", sessions.Raw)
	}

	in := h.expect(h.do("POST", "/api/v1/auth/introspect", client, M{"token": access}), 200, "")
	if !strings.Contains(in.Raw, `"active":true`) || !strings.Contains(in.Raw, `"sub":"`+uid) {
		t.Fatalf("introspection: %s", in.Raw)
	}

	rotated := h.expect(h.do("POST", "/api/v1/auth/refresh", client, M{"refresh_token": refresh}), 200, "")
	h.expect(h.do("POST", "/api/v1/auth/logout", client, M{"refresh_token": rotated.get(t, "refresh_token")}), 204, "")
	h.expect(h.do("GET", "/api/v1/users/me", rotated.get(t, "access_token"), nil), 401, "invalid_token")
	in = h.expect(h.do("POST", "/api/v1/auth/introspect", client, M{"token": rotated.get(t, "access_token")}), 200, "")
	if !strings.Contains(in.Raw, `"active":false`) {
		t.Fatalf("logged-out token still active: %s", in.Raw)
	}
	h.expect(h.do("POST", "/api/v1/auth/refresh", client, M{"refresh_token": rotated.get(t, "refresh_token")}), 401, "invalid_refresh_token")

	audit := h.expect(h.do("GET", base+"/audit-events?type=user.logout", adminKey, nil), 200, "")
	if audit.Body.Meta.Pagination.Total != 1 || !strings.Contains(audit.Raw, uid) {
		t.Fatalf("audit trail: %s", audit.Raw)
	}
}

func TestLogoutWithAccessToken(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	_, access, refresh := h.user(client, "ada@example.com")
	h.expect(h.do("POST", "/api/v1/auth/logout", access, nil), 204, "")
	h.expect(h.do("GET", "/api/v1/users/me", access, nil), 401, "invalid_token")
	h.expect(h.do("POST", "/api/v1/auth/refresh", client, M{"refresh_token": refresh}), 401, "invalid_refresh_token")
	h.expect(h.do("POST", "/api/v1/auth/logout", "", nil), 401, "unauthenticated")
}

func TestEnvelopeAndHeaders(t *testing.T) {
	h := newHarness(t, nil)
	r := h.do("GET", "/api/v1/users/me", "", nil, "X-Request-ID", "trace-123")
	h.expect(r, 401, "unauthenticated")
	if r.Body.Meta.RequestID != "trace-123" || r.Header.Get("X-Request-ID") != "trace-123" {
		t.Fatalf("inbound request id not echoed: %s", r.Raw)
	}
	if r.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 without WWW-Authenticate")
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
		"Referrer-Policy": "no-referrer", "Content-Type": "application/json; charset=utf-8",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if r.Header.Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy")
	}
	// A hostile request id is replaced, never reflected.
	r = h.do("GET", "/livez", "", nil, "X-Request-ID", "<script>alert(1)</script>")
	if id := r.Header.Get("X-Request-ID"); strings.Contains(id, "<") || len(id) != 36 {
		t.Fatalf("unsafe request id reflected: %q", id)
	}
	h.expect(h.do("GET", "/api/v1/nope", "", nil), 404, "route_not_found")
	r = h.expect(h.do("DELETE", "/api/v1/auth/login", "", nil), 405, "method_not_allowed")
	if r.Header.Get("Allow") == "" {
		t.Fatal("405 without Allow header")
	}
}

func TestOperationalEndpoints(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/livez", "/readyz", "/healthz"} {
		if r := h.do("GET", p, "", nil); r.Status != 200 || !strings.Contains(r.Raw, `"status":"ok"`) {
			t.Fatalf("%s: %d %s", p, r.Status, r.Raw)
		}
	}
	if r := h.do("GET", "/api/v1/openapi.yaml", "", nil); r.Status != 200 || !strings.HasPrefix(r.Raw, "openapi:") {
		t.Fatalf("openapi: %d %s", r.Status, r.Raw)
	}
	h.do("GET", "/api/v1/tenants/some-id/users", "", nil)
	m := h.do("GET", "/metrics", "", nil)
	for _, want := range []string{
		`keyora_http_requests_total{method="GET",route="/api/v1/tenants/{tenant_id}/users",status="401"} 1`,
		`keyora_http_request_duration_seconds_count{method="GET",route="/livez"} 1`,
	} {
		if !strings.Contains(m.Raw, want) {
			t.Errorf("metrics missing %s\n%s", want, m.Raw)
		}
	}
	if strings.Contains(m.Raw, "some-id") {
		t.Error("metrics labels contain raw path values (unbounded cardinality)")
	}
	off := newHarness(t, func(c *httpapi.Config) { c.MetricsEnabled = false })
	off.expect(off.do("GET", "/metrics", "", nil), 404, "route_not_found")
}

func TestMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	post := func(body string, headers ...string) response {
		return h.do("POST", "/api/v1/auth/login", client, body, headers...)
	}
	h.expect(post(`{"email":`), 400, "invalid_json")
	h.expect(post(``), 400, "invalid_json")
	h.expect(post(`[]`), 400, "invalid_json")
	h.expect(post(`"just a string"`), 400, "invalid_json")
	h.expect(post(`{"email":"a@b.co","password":"x"}{"email":"c@d.co"}`), 400, "invalid_json")
	h.expect(post(`{"email":"a@b.co","password":"x","is_admin":true}`), 400, "invalid_json")
	h.expect(post(`{"email":123,"password":"x"}`), 400, "invalid_json")
	h.expect(post(`{"email":"a@b.co","password":"x"}`, "Content-Type", "text/plain"), 400, "unsupported_media_type")
	h.expect(post(`{"email":"a@b.co","password":"`+strings.Repeat("x", 2<<20)+`"}`), 413, "payload_too_large")
	// Deeply nested JSON must be rejected, not crash the server.
	h.expect(post(strings.Repeat(`{"a":`, 100000)+"1"+strings.Repeat("}", 100000)), 400, "invalid_json")

	r := h.expect(h.do("POST", "/api/v1/auth/register", client, M{"email": "nope", "password": password}), 400, "validation_failed")
	if r.Body.Error.Details["email"] == "" {
		t.Fatalf("validation error does not name the field: %s", r.Raw)
	}
	h.expect(h.do("GET", "/api/v1/tenants?limit=0", adminKey, nil), 400, "validation_failed")
	h.expect(h.do("GET", "/api/v1/tenants?limit=1000", adminKey, nil), 400, "validation_failed")
	h.expect(h.do("GET", "/api/v1/tenants?offset=-1", adminKey, nil), 400, "validation_failed")
	h.expect(h.do("GET", "/api/v1/tenants?limit=abc", adminKey, nil), 400, "validation_failed")
}

func TestInjectionPayloadsAreInert(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	h.user(client, "ada@example.com")
	for _, p := range []string{`' OR '1'='1`, `ada@example.com' --`, `"; DROP TABLE users; --`, `admin'/*`, `%`, `\`} {
		h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": p, "password": p}), 401, "invalid_credentials")
		// Repeated wrong passwords eventually lock the account; either way a payload never signs in.
		if r := h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": p}); r.Status != 401 && r.Status != 423 {
			t.Fatalf("payload %q as password: %d %s", p, r.Status, r.Raw)
		}
		r := h.expect(h.do("GET", "/api/v1/tenants/"+tid+"/users?email="+url.QueryEscape(p)+"&status="+url.QueryEscape(p), adminKey, nil), 200, "")
		if r.Body.Meta.Pagination.Total != 0 {
			t.Fatalf("filter payload %q matched rows: %s", p, r.Raw)
		}
		h.expect(h.do("GET", "/api/v1/tenants/"+tid+"/users/"+url.PathEscape(p), adminKey, nil), 404, "not_found")
		h.expect(h.do("POST", "/api/v1/auth/login", url.QueryEscape(p)+":"+p, M{"email": "ada@example.com", "password": password}), 401, "invalid_client")
	}
	r := h.expect(h.do("GET", "/api/v1/tenants/"+tid+"/users", adminKey, nil), 200, "")
	if r.Body.Meta.Pagination.Total != 1 {
		t.Fatalf("user table changed: %s", r.Raw)
	}
	// Markup in a name is stored as data and returned JSON-escaped.
	xss := `<script>alert(1)</script>`
	r = h.expect(h.do("POST", "/api/v1/auth/register", client, M{"email": "eve@example.com", "password": password, "name": xss}), 201, "")
	if strings.Contains(r.Raw, "<script>") || r.get(t, "name") != xss {
		t.Fatalf("markup not escaped in transit or not preserved: %s", r.Raw)
	}
}

func TestClientCredentialTransport(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	id, secret, _ := strings.Cut(client, ":")
	body := M{"email": "ada@example.com", "password": password}

	h.expect(h.do("POST", "/api/v1/auth/register", "", M{"client_id": id, "client_secret": secret, "email": "ada@example.com", "password": password}), 201, "")
	h.expect(h.do("POST", "/api/v1/auth/login", "", M{"client_id": id, "client_secret": secret, "email": "ada@example.com", "password": password}), 200, "")
	h.expect(h.do("POST", "/api/v1/auth/login", client, body), 200, "")
	h.expect(h.do("POST", "/api/v1/auth/login", "", body), 401, "invalid_client")
	h.expect(h.do("POST", "/api/v1/auth/login", id+":wrong", body), 401, "invalid_client")
	h.expect(h.do("POST", "/api/v1/auth/login", "", M{"client_id": id, "email": "ada@example.com", "password": password}), 401, "invalid_client")
	// The admin key is not an application credential.
	h.expect(h.do("POST", "/api/v1/auth/login", adminKey, body), 401, "invalid_client")
}

func TestPrivilegeEscalation(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	uid, access, _ := h.user(client, "mallory@example.com")
	base := "/api/v1/tenants/" + tid

	roles := h.expect(h.do("GET", base+"/roles", adminKey, nil), 200, "")
	var list []struct{ ID string }
	json.Unmarshal(roles.Body.Data, &list)
	adminRole := list[0].ID

	// An ordinary user is refused by every management endpoint of their own tenant.
	attempts := []struct {
		method, path string
		body         any
	}{
		{"GET", base, nil},
		{"GET", base + "/users", nil},
		{"POST", base + "/users", M{"email": "x@example.com", "password": password}},
		{"GET", base + "/users/" + uid, nil},
		{"PATCH", base + "/users/" + uid, M{"email_verified": true}},
		{"DELETE", base + "/users/" + uid, nil},
		{"POST", base + "/users/" + uid + "/unlock", nil},
		{"GET", base + "/users/" + uid + "/roles", nil},
		{"PUT", base + "/users/" + uid + "/roles/" + adminRole, nil}, // self-promotion
		{"DELETE", base + "/users/" + uid + "/roles/" + adminRole, nil},
		{"POST", base + "/roles", M{"name": "god", "permissions": []string{"keyora:admin"}}},
		{"GET", base + "/roles", nil},
		{"GET", base + "/roles/" + adminRole, nil},
		{"PATCH", base + "/roles/" + adminRole, M{"description": "x"}},
		{"DELETE", base + "/roles/" + adminRole, nil},
		{"PUT", base + "/roles/" + adminRole + "/permissions", M{"permissions": []string{}}},
		{"POST", base + "/permissions", M{"name": "x:y"}},
		{"GET", base + "/permissions", nil},
		{"DELETE", base + "/permissions/whatever", nil},
		{"POST", base + "/applications", M{"name": "evil"}},
		{"GET", base + "/applications", nil},
		{"GET", base + "/applications/x", nil},
		{"PATCH", base + "/applications/x", M{"name": "y"}},
		{"DELETE", base + "/applications/x", nil},
		{"POST", base + "/applications/x/rotate-secret", nil},
		{"GET", base + "/sessions", nil},
		{"DELETE", base + "/sessions/x", nil},
		{"GET", base + "/audit-events", nil},
		{"POST", "/api/v1/tenants", M{"slug": "mine", "name": "Mine"}},
		{"GET", "/api/v1/tenants", nil},
		{"PATCH", "/api/v1/tenants/" + tid, M{"status": "suspended"}},
	}
	for _, a := range attempts {
		for who, token := range map[string]string{"user": access, "anonymous": "", "garbage": "not-a-token", "almost the admin key": adminKey + "x"} {
			r := h.do(a.method, a.path, token, a.body)
			want := 401
			if who == "user" {
				want = 403
			}
			if r.Status != want {
				t.Errorf("%s %s as %s: got %d (%s), want %d", a.method, a.path, who, r.Status, r.code(), want)
			}
		}
	}

	// Self-service cannot be used to change privileged fields.
	h.expect(h.do("PATCH", "/api/v1/users/me", access, M{"name": "M", "status": "active"}), 400, "invalid_json")
	h.expect(h.do("PATCH", "/api/v1/users/me", access, M{"name": "M", "email_verified": true}), 400, "invalid_json")
	h.expect(h.do("PATCH", "/api/v1/users/me", access, M{"name": "M", "roles": []string{"keyora-admin"}}), 400, "invalid_json")
	h.expect(h.do("POST", "/api/v1/auth/register", client, M{"email": "z@example.com", "password": password, "roles": []string{"keyora-admin"}}), 400, "invalid_json")
	me := h.expect(h.do("GET", "/api/v1/users/me", access, nil), 200, "")
	if !strings.Contains(me.Raw, `"roles":[]`) || !strings.Contains(me.Raw, `"email_verified":false`) {
		t.Fatalf("user gained privileges: %s", me.Raw)
	}

	// The reserved permission cannot be minted or smuggled into a role by name.
	h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "keyora:super"}), 400, "validation_failed")

	// Root key has no user identity and cannot act on /users/me.
	h.expect(h.do("GET", "/api/v1/users/me", adminKey, nil), 403, "forbidden")

	// Once promoted by root, the same token works immediately (roles are read
	// live) and stops working the moment the role is taken away.
	h.makeAdmin(tid, uid)
	h.expect(h.do("GET", base+"/users", access, nil), 200, "")
	h.expect(h.do("POST", "/api/v1/tenants", access, M{"slug": "mine", "name": "Mine"}), 403, "forbidden") // still not root
	h.expect(h.do("DELETE", base+"/users/"+uid+"/roles/"+adminRole, adminKey, nil), 204, "")
	h.expect(h.do("GET", base+"/users", access, nil), 403, "forbidden")
}

func TestCrossTenantAccessIsDenied(t *testing.T) {
	h := newHarness(t, nil)
	tidA, clientA := h.tenant("acme")
	tidB, clientB := h.tenant("beta")
	adminA, accessA, refreshA := h.user(clientA, "admin@example.com")
	h.makeAdmin(tidA, adminA)
	victim, victimAccess, _ := h.user(clientB, "victim@example.com")
	a, b := "/api/v1/tenants/"+tidA, "/api/v1/tenants/"+tidB

	appsB := h.expect(h.do("GET", b+"/applications", adminKey, nil), 200, "")
	var apps []struct{ ID string }
	json.Unmarshal(appsB.Body.Data, &apps)
	sessB := h.expect(h.do("GET", b+"/sessions", adminKey, nil), 200, "")
	var sessions []struct{ ID string }
	json.Unmarshal(sessB.Body.Data, &sessions)

	h.expect(h.do("GET", a+"/users", accessA, nil), 200, "") // sanity: A's admin works in A

	// Tenant B named in the path: refused outright.
	for _, r := range []response{
		h.do("GET", b, accessA, nil),
		h.do("GET", b+"/users", accessA, nil),
		h.do("GET", b+"/users/"+victim, accessA, nil),
		h.do("PATCH", b+"/users/"+victim, accessA, M{"status": "disabled"}),
		h.do("DELETE", b+"/users/"+victim, accessA, nil),
		h.do("POST", b+"/users", accessA, M{"email": "plant@example.com", "password": password}),
		h.do("GET", b+"/applications", accessA, nil),
		h.do("POST", b+"/applications/"+apps[0].ID+"/rotate-secret", accessA, nil),
		h.do("GET", b+"/sessions", accessA, nil),
		h.do("DELETE", b+"/sessions/"+sessions[0].ID, accessA, nil),
		h.do("GET", b+"/audit-events", accessA, nil),
		h.do("POST", b+"/roles", accessA, M{"name": "backdoor"}),
	} {
		h.expect(r, 403, "forbidden")
	}

	// Own tenant in the path, tenant B's IDs in the rest: not found.
	for _, r := range []response{
		h.do("GET", a+"/users/"+victim, accessA, nil),
		h.do("PATCH", a+"/users/"+victim, accessA, M{"status": "disabled"}),
		h.do("DELETE", a+"/users/"+victim, accessA, nil),
		h.do("POST", a+"/users/"+victim+"/unlock", accessA, nil),
		h.do("GET", a+"/users/"+victim+"/roles", accessA, nil),
		h.do("GET", a+"/applications/"+apps[0].ID, accessA, nil),
		h.do("DELETE", a+"/applications/"+apps[0].ID, accessA, nil),
		h.do("POST", a+"/applications/"+apps[0].ID+"/rotate-secret", accessA, nil),
		h.do("DELETE", a+"/sessions/"+sessions[0].ID, accessA, nil),
		h.do("DELETE", "/api/v1/users/me/sessions/"+sessions[0].ID, accessA, nil),
	} {
		h.expect(r, 404, "not_found")
	}
	// A's admin role cannot be granted to B's user.
	rolesA := h.expect(h.do("GET", a+"/roles", accessA, nil), 200, "")
	var roles []struct{ ID string }
	json.Unmarshal(rolesA.Body.Data, &roles)
	h.expect(h.do("PUT", a+"/users/"+victim+"/roles/"+roles[0].ID, accessA, nil), 404, "not_found")

	// Tokens do not cross tenants through the auth endpoints either.
	h.expect(h.do("POST", "/api/v1/auth/refresh", clientB, M{"refresh_token": refreshA}), 401, "invalid_refresh_token")
	in := h.expect(h.do("POST", "/api/v1/auth/introspect", clientB, M{"token": accessA}), 200, "")
	if !strings.Contains(in.Raw, `"active":false`) || strings.Contains(in.Raw, adminA) {
		t.Fatalf("tenant B introspected tenant A's token: %s", in.Raw)
	}
	h.expect(h.do("POST", "/api/v1/auth/login", clientB, M{"email": "admin@example.com", "password": password}), 401, "invalid_credentials")

	// Nothing above harmed the victim.
	h.expect(h.do("GET", "/api/v1/users/me", victimAccess, nil), 200, "")
	h.expect(h.do("GET", "/api/v1/users/me", accessA, nil), 200, "")
}

func TestSessionSelfService(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	_, laptop, _ := h.user(client, "ada@example.com")
	phone := h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": password}), 200, "")
	_, other, _ := h.user(client, "bob@example.com")

	list := h.expect(h.do("GET", "/api/v1/users/me/sessions", laptop, nil), 200, "")
	if list.Body.Meta.Pagination.Total != 2 {
		t.Fatalf("want 2 device sessions: %s", list.Raw)
	}
	// Bob cannot end Ada's session.
	h.expect(h.do("DELETE", "/api/v1/users/me/sessions/"+phone.get(t, "session_id"), other, nil), 404, "not_found")
	h.expect(h.do("DELETE", "/api/v1/users/me/sessions/"+phone.get(t, "session_id"), laptop, nil), 204, "")
	h.expect(h.do("GET", "/api/v1/users/me", phone.get(t, "access_token"), nil), 401, "invalid_token")
	h.expect(h.do("GET", "/api/v1/users/me", laptop, nil), 200, "")

	h.expect(h.do("POST", "/api/v1/users/me/password", laptop, M{"current_password": "wrong", "new_password": "a brand new password"}), 401, "invalid_credentials")
	h.expect(h.do("POST", "/api/v1/users/me/password", laptop, M{"current_password": password, "new_password": "a brand new password"}), 204, "")
	h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": password}), 401, "invalid_credentials")
}

func TestBruteForceOverHTTP(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	uid, _, _ := h.user(client, "ada@example.com")
	for i := 0; i < 3; i++ {
		h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": "guess number " + string(rune('a'+i))}), 401, "invalid_credentials")
	}
	r := h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": password}), 423, "account_locked")
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("locked response has no Retry-After")
	}
	h.expect(h.do("POST", "/api/v1/tenants/"+tid+"/users/"+uid+"/unlock", adminKey, nil), 200, "")
	h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": password}), 200, "")
}

func TestRateLimiting(t *testing.T) {
	h := newHarness(t, func(c *httpapi.Config) { c.Limiter = ratelimit.New(60, 5) })
	_, client := h.tenant("acme")
	limited := 0
	for i := 0; i < 12; i++ {
		r := h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": "nope nope nope"})
		if r.Status == 429 {
			limited++
			if r.code() != "rate_limited" || r.Header.Get("Retry-After") == "" {
				t.Fatalf("bad 429: %s %v", r.Raw, r.Header)
			}
		}
	}
	if limited != 7 {
		t.Fatalf("%d of 12 requests were limited, want 7 (burst of 5)", limited)
	}
	// Only credential endpoints are limited.
	h.expect(h.do("GET", "/livez", "", nil), 200, "")
	h.expect(h.do("GET", "/api/v1/tenants", adminKey, nil), 200, "")
}

func TestProxyHeaderTrust(t *testing.T) {
	spoof := []string{"X-Forwarded-For", "9.9.9.9, 10.0.0.7"}
	events := func(h *harness, tid string) string {
		return h.do("GET", "/api/v1/tenants/"+tid+"/audit-events?type=user.registered", adminKey, nil).Raw
	}
	untrusted := newHarness(t, nil)
	tid, client := untrusted.tenant("acme")
	untrusted.do("POST", "/api/v1/auth/register", client, M{"email": "a@example.com", "password": password}, spoof...)
	if raw := events(untrusted, tid); !strings.Contains(raw, `"ip":"127.0.0.1"`) {
		t.Fatalf("X-Forwarded-For was honoured without KEYORA_TRUST_PROXY_HEADERS: %s", raw)
	}
	trusted := newHarness(t, func(c *httpapi.Config) { c.TrustProxyHeaders = true })
	tid, client = trusted.tenant("acme")
	trusted.do("POST", "/api/v1/auth/register", client, M{"email": "a@example.com", "password": password}, spoof...)
	if raw := events(trusted, tid); !strings.Contains(raw, `"ip":"10.0.0.7"`) {
		t.Fatalf("should use the right-most (proxy-appended) address, never the client-supplied one: %s", raw)
	}
}

func TestCORS(t *testing.T) {
	h := newHarness(t, nil)
	tid, _ := h.tenant("acme")
	spa := h.expect(h.do("POST", "/api/v1/tenants/"+tid+"/applications", adminKey,
		M{"name": "spa", "type": "public", "allowed_origins": []string{"https://app.example.com"}}), 201, "")
	if spa.get(t, "client_secret") != "" {
		t.Fatal("public application received a secret")
	}
	id := spa.get(t, "client_id")
	body := M{"client_id": id, "email": "ada@example.com", "password": password}

	pre := h.do("OPTIONS", "/api/v1/auth/login", "", nil, "Origin", "https://app.example.com", "Access-Control-Request-Method", "POST")
	if pre.Status != 204 || pre.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		!strings.Contains(pre.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight for a registered origin: %d %v", pre.Status, pre.Header)
	}
	if pre.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentialed CORS must stay off: tokens are not cookies")
	}
	pre = h.do("OPTIONS", "/api/v1/auth/login", "", nil, "Origin", "https://evil.example", "Access-Control-Request-Method", "POST")
	if pre.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("preflight granted to an unregistered origin: %v", pre.Header)
	}

	ok := h.expect(h.do("POST", "/api/v1/auth/register", "", body, "Origin", "https://app.example.com"), 201, "")
	if ok.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || ok.Header.Get("Vary") != "Origin" {
		t.Fatalf("missing CORS headers: %v", ok.Header)
	}
	// The server itself refuses a public client from a foreign origin; it
	// does not rely on the browser enforcing CORS.
	bad := h.expect(h.do("POST", "/api/v1/auth/login", "", body, "Origin", "https://evil.example"), 403, "origin_not_allowed")
	if bad.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin was allowed to read the response")
	}
	for _, o := range []string{"https://app.example.com.evil.example", "http://app.example.com", "null", "https://APP.example.com"} {
		if r := h.do("GET", "/livez", "", nil, "Origin", o); r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("origin %q matched loosely", o)
		}
	}
	// Statically configured origins work without any application.
	if r := h.do("GET", "/livez", "", nil, "Origin", "https://console.test"); r.Header.Get("Access-Control-Allow-Origin") != "https://console.test" {
		t.Fatal("configured origin not allowed")
	}
	// Removing the origin from the application takes effect immediately.
	h.expect(h.do("PATCH", "/api/v1/tenants/"+tid+"/applications/"+spa.get(t, "id"), adminKey, M{"allowed_origins": []string{}}), 200, "")
	if r := h.do("GET", "/livez", "", nil, "Origin", "https://app.example.com"); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("removed origin still allowed")
	}
	// Public applications can never introspect.
	h.expect(h.do("POST", "/api/v1/auth/introspect", "", M{"client_id": id, "token": "x"}), 401, "invalid_client")
}

func TestOAuthClientCredentials(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	id, secret, _ := strings.Cut(client, ":")
	post := func(form url.Values, basic bool) (int, map[string]any) {
		req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(id, secret)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	status, body := post(url.Values{"grant_type": {"client_credentials"}}, true)
	if status != 200 || body["token_type"] != "Bearer" || body["access_token"] == nil || body["refresh_token"] != nil {
		t.Fatalf("token response: %d %v", status, body)
	}
	if _, enveloped := body["data"]; enveloped {
		t.Fatal("the OAuth endpoint must use the RFC 6749 wire format, not the envelope")
	}
	status, _ = post(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, false)
	if status != 200 {
		t.Fatalf("client_secret_post: %d", status)
	}
	if status, body = post(url.Values{"grant_type": {"password"}, "username": {"a"}, "password": {"b"}}, true); status != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant: %d %v", status, body)
	}
	if status, body = post(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"nope"}}, false); status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("bad secret: %d %v", status, body)
	}
	in := h.expect(h.do("POST", "/api/v1/auth/introspect", client, M{"token": body["access_token"]}), 200, "")
	if !strings.Contains(in.Raw, `"active":false`) {
		t.Fatalf("introspecting a non-token: %s", in.Raw)
	}
}

func TestManagementCRUD(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	base := "/api/v1/tenants/" + tid

	h.expect(h.do("POST", "/api/v1/tenants", adminKey, M{"slug": "acme", "name": "Again"}), 409, "slug_taken")
	h.expect(h.do("GET", base, adminKey, nil), 200, "")
	h.expect(h.do("GET", "/api/v1/tenants/unknown", adminKey, nil), 404, "not_found")
	h.expect(h.do("PATCH", base, adminKey, M{"slug": "other"}), 400, "validation_failed")

	app := h.expect(h.do("POST", base+"/applications", adminKey, M{"name": "api", "redirect_uris": []string{"https://api.test/cb"}, "access_token_ttl_seconds": 300}), 201, "")
	appID, oldSecret := app.get(t, "id"), app.get(t, "client_secret")
	got := h.expect(h.do("GET", base+"/applications/"+appID, adminKey, nil), 200, "")
	if strings.Contains(got.Raw, "secret") {
		t.Fatalf("the client secret (or its hash) is readable after creation: %s", got.Raw)
	}
	list := h.expect(h.do("GET", base+"/applications?limit=1&offset=1", adminKey, nil), 200, "")
	if p := list.Body.Meta.Pagination; p.Total != 2 || p.Limit != 1 || p.Offset != 1 || strings.Contains(list.Raw, "secret") {
		t.Fatalf("pagination: %s", list.Raw)
	}
	h.expect(h.do("POST", base+"/applications", adminKey, M{"name": "api"}), 409, "name_taken")
	rot := h.expect(h.do("POST", base+"/applications/"+appID+"/rotate-secret", adminKey, nil), 200, "")
	cid := app.get(t, "client_id")
	h.expect(h.do("POST", "/api/v1/auth/login", cid+":"+oldSecret, M{"email": "a@b.co", "password": password}), 401, "invalid_client")
	h.expect(h.do("POST", "/api/v1/auth/login", cid+":"+rot.get(t, "client_secret"), M{"email": "a@b.co", "password": password}), 401, "invalid_credentials")
	h.expect(h.do("DELETE", base+"/applications/"+appID, adminKey, nil), 204, "")
	h.expect(h.do("DELETE", base+"/applications/"+appID, adminKey, nil), 404, "not_found")

	u := h.expect(h.do("POST", base+"/users", adminKey, M{"email": "Bob@Example.com", "password": password, "name": "Bob", "email_verified": true}), 201, "")
	uid := u.get(t, "id")
	h.expect(h.do("POST", base+"/users", adminKey, M{"email": "bob@example.com", "password": password}), 409, "email_taken")
	h.expect(h.do("PATCH", base+"/users/"+uid, adminKey, M{"password": "sneaky new password"}), 400, "validation_failed")
	login := h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "bob@example.com", "password": password}), 200, "")
	h.expect(h.do("PATCH", base+"/users/"+uid, adminKey, M{"status": "disabled"}), 200, "")
	h.expect(h.do("GET", "/api/v1/users/me", login.get(t, "access_token"), nil), 401, "invalid_token")
	if r := h.expect(h.do("GET", base+"/users?status=disabled&email=BOB", adminKey, nil), 200, ""); r.Body.Meta.Pagination.Total != 1 {
		t.Fatalf("filtering: %s", r.Raw)
	}
	if r := h.expect(h.do("GET", base+"/sessions?user_id="+uid+"&active=true", adminKey, nil), 200, ""); r.Body.Meta.Pagination.Total != 0 {
		t.Fatalf("disabled user still has active sessions: %s", r.Raw)
	}

	perm := h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "orders:read"}), 201, "")
	h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "orders:read"}), 409, "name_taken")
	h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "has spaces"}), 400, "validation_failed")
	h.expect(h.do("POST", base+"/permissions", adminKey, M{"name": "ok:name", "description": "bad\u0000byte"}), 400, "validation_failed")
	role := h.expect(h.do("POST", base+"/roles", adminKey, M{"name": "viewer"}), 201, "")
	rid := role.get(t, "id")
	h.expect(h.do("PUT", base+"/roles/"+rid+"/permissions", adminKey, M{"permissions": []string{"nope"}}), 400, "validation_failed")
	h.expect(h.do("PUT", base+"/roles/"+rid+"/permissions", adminKey, M{}), 400, "validation_failed")
	set := h.expect(h.do("PUT", base+"/roles/"+rid+"/permissions", adminKey, M{"permissions": []string{"orders:read"}}), 200, "")
	if !strings.Contains(set.Raw, `"permissions":["orders:read"]`) {
		t.Fatalf("role: %s", set.Raw)
	}
	h.expect(h.do("PATCH", base+"/roles/"+rid, adminKey, M{"name": "reader", "description": "Read only"}), 200, "")
	h.expect(h.do("PUT", base+"/users/"+uid+"/roles/"+rid, adminKey, nil), 204, "")
	h.expect(h.do("PUT", base+"/users/"+uid+"/roles/"+rid, adminKey, nil), 204, "") // idempotent
	h.expect(h.do("PUT", base+"/users/"+uid+"/roles/unknown", adminKey, nil), 404, "not_found")
	if r := h.expect(h.do("GET", base+"/users/"+uid+"/roles", adminKey, nil), 200, ""); !strings.Contains(r.Raw, `"name":"reader"`) {
		t.Fatalf("user roles: %s", r.Raw)
	}
	h.expect(h.do("DELETE", base+"/permissions/"+perm.get(t, "id"), adminKey, nil), 204, "")
	if r := h.expect(h.do("GET", base+"/roles/"+rid, adminKey, nil), 200, ""); !strings.Contains(r.Raw, `"permissions":[]`) {
		t.Fatalf("deleted permission still on role: %s", r.Raw)
	}
	h.expect(h.do("DELETE", base+"/roles/"+rid, adminKey, nil), 204, "")
	h.expect(h.do("DELETE", base+"/users/"+uid, adminKey, nil), 204, "")
	h.expect(h.do("GET", base+"/users/"+uid, adminKey, nil), 404, "not_found")

	h.expect(h.do("PATCH", base, adminKey, M{"status": "suspended"}), 200, "")
	h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "bob@example.com", "password": password}), 401, "invalid_client")
}

func TestRootAccessDisabledWithoutAdminKey(t *testing.T) {
	h := newHarness(t, func(c *httpapi.Config) { c.AdminKey = "" })
	h.expect(h.do("GET", "/api/v1/tenants", "", nil), 401, "unauthenticated")
	h.expect(h.do("GET", "/api/v1/tenants", adminKey, nil), 401, "invalid_token")
}

func TestEmailFlowsOverHTTP(t *testing.T) {
	h := newHarness(t, nil)
	_, client := h.tenant("acme")
	h.user(client, "ada@example.com")
	tokenFrom := func(prefix string) string {
		msg, ok := h.env.Mail.Last("ada@example.com")
		if !ok {
			t.Fatal("no email sent")
		}
		return strings.Fields(msg.Body[strings.Index(msg.Body, prefix):])[0]
	}
	h.expect(h.do("POST", "/api/v1/auth/email-verification/confirm", "", M{"token": "kyv_wrong"}), 400, "invalid_verification_token")
	h.expect(h.do("POST", "/api/v1/auth/email-verification/confirm", "", M{"token": tokenFrom("kyv_")}), 204, "")

	// Identical answers for known and unknown addresses.
	known := h.do("POST", "/api/v1/auth/password/forgot", client, M{"email": "ada@example.com"})
	unknown := h.do("POST", "/api/v1/auth/password/forgot", client, M{"email": "nobody@example.com"})
	if known.Status != 202 || unknown.Status != 202 || known.Raw != unknown.Raw {
		t.Fatalf("forgot-password reveals account existence: %d %q vs %d %q", known.Status, known.Raw, unknown.Status, unknown.Raw)
	}
	h.expect(h.do("POST", "/api/v1/auth/password/forgot", "", M{"email": "ada@example.com"}), 401, "invalid_client")
	reset := tokenFrom("kyp_")
	h.expect(h.do("POST", "/api/v1/auth/password/reset", "", M{"token": reset, "new_password": "x"}), 400, "validation_failed")
	h.expect(h.do("POST", "/api/v1/auth/password/reset", "", M{"token": reset, "new_password": "a brand new password"}), 204, "")
	h.expect(h.do("POST", "/api/v1/auth/password/reset", "", M{"token": reset, "new_password": "another new password"}), 400, "invalid_verification_token")
	h.expect(h.do("POST", "/api/v1/auth/login", client, M{"email": "ada@example.com", "password": "a brand new password"}), 200, "")
}
