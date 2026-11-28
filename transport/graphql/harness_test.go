package graphqlapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	graphqlapi "github.com/rabbicse/keyora/transport/graphql"
)

const (
	adminKey = "test-admin-key-0123456789abcdef0123456789"
	password = "correct horse battery"
)

// setup is what a test may change before the server starts.
type setup struct {
	API     httpapi.Config
	GraphQL graphqlapi.Options
	Store   store.Store
}

// harness serves the real handler the way a Keyora binary does: mounted on
// the REST API, behind its middleware.
type harness struct {
	t    *testing.T
	env  *testutil.Env
	srv  *httptest.Server
	logs *logBuffer
}

func newHarness(t *testing.T, mod func(*setup)) *harness {
	t.Helper()
	s := setup{Store: memory.New()}
	if mod != nil {
		mod(&s)
	}
	h := &harness{t: t, env: testutil.NewEnv(t, s.Store, nil), logs: &logBuffer{}}
	h.srv = h.serve(mod)
	return h
}

// serve starts one more server on the harness's service, as a second Keyora
// instance on the same database would be.
func (h *harness) serve(mod func(*setup)) *httptest.Server {
	h.t.Helper()
	s := setup{
		API:     httpapi.Config{AdminKey: adminKey, Version: "test"},
		GraphQL: graphqlapi.Options{Introspection: true},
	}
	if mod != nil {
		mod(&s)
	}
	log := slog.New(slog.NewTextHandler(h.logs, nil))
	api := httpapi.New(h.env.Svc, s.API, log)
	handler, err := graphqlapi.NewHandler(api.Gate(), log, s.GraphQL)
	if err != nil {
		h.t.Fatal(err)
	}
	api.Mount(graphqlapi.Route, handler)
	srv := httptest.NewServer(api)
	h.t.Cleanup(srv.Close)
	return srv
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type gqlError struct {
	Message    string `json:"message"`
	Path       []any  `json:"path"`
	Extensions struct {
		Code      string            `json:"code"`
		RequestID string            `json:"request_id"`
		Details   map[string]string `json:"details"`
	} `json:"extensions"`
}

type result struct {
	t      *testing.T
	Status int
	Header http.Header
	Raw    string
	Data   any
	Errors []gqlError
}

type M = map[string]any

// post sends a raw body to /graphql.
func (h *harness) post(auth, contentType string, body io.Reader, headers ...string) result {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/graphql", body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
	out := result{t: h.t, Status: res.StatusCode, Header: res.Header, Raw: string(raw)}
	var parsed struct {
		Data   any        `json:"data"`
		Errors []gqlError `json:"errors"`
	}
	_ = json.Unmarshal(raw, &parsed)
	out.Data, out.Errors = parsed.Data, parsed.Errors
	return out
}

// gql executes a document. auth is a bearer token, or "id:secret" for HTTP Basic.
func (h *harness) gql(auth, query string, vars M, headers ...string) result {
	h.t.Helper()
	body, _ := json.Marshal(M{"query": query, "variables": vars})
	return h.post(auth, "application/json", bytes.NewReader(body), headers...)
}

// ok requires a response without errors.
func (h *harness) ok(r result) result {
	h.t.Helper()
	if r.Status != 200 || len(r.Errors) != 0 {
		h.t.Fatalf("got %d with errors, want success\nbody: %s", r.Status, r.Raw)
	}
	return r
}

// fails requires exactly one error with the given code, on a field that
// resolved to null.
func (h *harness) fails(r result, code string) result {
	h.t.Helper()
	if r.Status != 200 || len(r.Errors) != 1 || r.Errors[0].Extensions.Code != code {
		h.t.Fatalf("got %d %v, want one %q error\nbody: %s", r.Status, r.codes(), code, r.Raw)
	}
	if len(r.Errors[0].Path) > 0 {
		if v := r.at(r.Errors[0].Path[0].(string)); v != nil {
			h.t.Fatalf("failed field carries data: %s", r.Raw)
		}
	}
	return r
}

func (r result) codes() []string {
	var out []string
	for _, e := range r.Errors {
		out = append(out, e.Extensions.Code)
	}
	return out
}

// codeAt is the error code of the root field with the given alias, or "".
func (r result) codeAt(alias string) string {
	for _, e := range r.Errors {
		if len(e.Path) > 0 && e.Path[0] == alias {
			return e.Extensions.Code
		}
	}
	return ""
}

// at walks the data by a dotted path ("users.items.0.id"); nil when absent.
func (r result) at(path string) any {
	v := r.Data
	for _, key := range strings.Split(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			v = node[key]
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
	}
	return v
}

func (r result) str(path string) string {
	r.t.Helper()
	s, ok := r.at(path).(string)
	if !ok {
		r.t.Fatalf("no string at %q\nbody: %s", path, r.Raw)
	}
	return s
}

func (r result) num(path string) int {
	r.t.Helper()
	n, ok := r.at(path).(float64)
	if !ok {
		r.t.Fatalf("no number at %q\nbody: %s", path, r.Raw)
	}
	return int(n)
}

// tenant creates a tenant with one confidential application and returns
// (tenantID, "client_id:client_secret").
func (h *harness) tenant(slug string) (string, string) {
	h.t.Helper()
	r := h.ok(h.gql(adminKey, `mutation($slug: String!) { createTenant(slug: $slug, name: $slug) { id } }`, M{"slug": slug}))
	id := r.str("createTenant.id")
	app := h.ok(h.gql(adminKey, `mutation($t: ID!) {
		createApplication(tenantId: $t, input: {name: "web"}) { application { clientId } clientSecret }
	}`, M{"t": id}))
	return id, app.str("createApplication.application.clientId") + ":" + app.str("createApplication.clientSecret")
}

const loginMutation = `mutation($email: String!, $password: String!) {
	login(email: $email, password: $password) { tokens { accessToken refreshToken sessionId tokenType expiresIn } user { id email } }
}`

// user registers and signs in, returning (userID, accessToken, refreshToken).
func (h *harness) user(client, email string) (string, string, string) {
	h.t.Helper()
	vars := M{"email": email, "password": password}
	u := h.ok(h.gql(client, `mutation($email: String!, $password: String!) {
		register(email: $email, password: $password, name: "Ada") { id }
	}`, vars))
	l := h.ok(h.gql(client, loginMutation, vars))
	return u.str("register.id"), l.str("login.tokens.accessToken"), l.str("login.tokens.refreshToken")
}

// adminRole returns the ID of the tenant's seeded administrator role.
func (h *harness) adminRole(tenantID string) string {
	h.t.Helper()
	r := h.ok(h.gql(adminKey, `query($t: ID!) { roles(tenantId: $t) { items { id name } } }`, M{"t": tenantID}))
	for i := range r.at("roles.items").([]any) {
		if r.str("roles.items."+strconv.Itoa(i)+".name") == "keyora-admin" {
			return r.str("roles.items." + strconv.Itoa(i) + ".id")
		}
	}
	h.t.Fatalf("tenant has no keyora-admin role: %s", r.Raw)
	return ""
}

func (h *harness) makeAdmin(tenantID, userID string) {
	h.t.Helper()
	h.ok(h.gql(adminKey, `mutation($t: ID!, $u: ID!, $r: ID!) { assignRole(tenantId: $t, userId: $u, roleId: $r) }`,
		M{"t": tenantID, "u": userID, "r": h.adminRole(tenantID)}))
}

// restLogin signs in through the REST API of the same server and returns the
// HTTP status.
func (h *harness) restLogin(client, email, pw string) int {
	h.t.Helper()
	body, _ := json.Marshal(M{"email": email, "password": pw})
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	id, secret, _ := strings.Cut(client, ":")
	req.SetBasicAuth(id, secret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}
