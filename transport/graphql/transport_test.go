package graphqlapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rabbicse/keyora/internal/config"
	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/server"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
	graphqlapi "github.com/rabbicse/keyora/transport/graphql"
)

// introspectionQuery is the full-schema query that client tooling sends,
// with nine levels of ofType.
const introspectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } }
}`

func TestIntrospection(t *testing.T) {
	on := newHarness(t, nil)
	r := on.ok(on.gql("", introspectionQuery, nil))
	if r.str("__schema.queryType.name") != "Query" || r.str("__schema.mutationType.name") != "Mutation" || r.at("__schema.subscriptionType") != nil {
		t.Fatalf("root types: %.300s", r.Raw)
	}
	// The schema documents itself.
	user := on.ok(on.gql("", `{ __type(name: "Mutation") { fields { name description } } }`, nil))
	documented := false
	for _, f := range user.at("__type.fields").([]any) {
		f := f.(map[string]any)
		if f["name"] == "login" {
			documented = strings.Contains(f["description"].(string), "Signs a user in")
		}
	}
	if !documented {
		t.Fatalf("descriptions are not served: %.300s", user.Raw)
	}

	off := newHarness(t, func(s *setup) { s.GraphQL.Introspection = false })
	for _, q := range []string{
		introspectionQuery,
		`{ __schema { types { name } } }`,
		`{ __type(name: "User") { name fields { name } } }`,
		`{ a: __schema { queryType { name } } }`,
	} {
		r := off.gql("", q, nil)
		if r.Status != 200 || r.at("__schema") != nil || r.at("__type") != nil || r.at("a") != nil {
			t.Errorf("introspection is off but %q answered: %.300s", q, r.Raw)
		}
		for _, leak := range []string{"TenantConnection", "ApplicationWithSecret", "emailVerified", "queryType"} {
			if strings.Contains(r.Raw, leak) {
				t.Errorf("introspection is off but the response to %q names %q: %.300s", q, leak, r.Raw)
			}
		}
	}
	// Nor do error messages suggest the names a caller might have meant.
	for _, q := range []string{`{ tenantz { total } }`, `{ tenants { totl } }`, `{ tenants(limt: 1) { total } }`, `mutation { token(input: {grantType: CLIENT_CREDENTIAL}) { scope } }`} {
		with, without := on.gql(adminKey, q, nil), off.gql(adminKey, q, nil)
		if !strings.Contains(with.Raw, "Did you mean") {
			t.Errorf("%s: expected a suggestion with introspection on: %s", q, with.Raw)
		}
		if len(without.Errors) == 0 || without.Errors[0].Extensions.Code != "invalid_query" || without.Errors[0].Message == "" ||
			strings.Contains(without.Raw, "Did you mean") || strings.Contains(without.Raw, `\"total\"`) || strings.Contains(without.Raw, "limit") || strings.Contains(without.Raw, "CLIENT_CREDENTIALS") {
			t.Errorf("%s: suggestion with introspection off: %s", q, without.Raw)
		}
	}
	// The API itself is unaffected, and so is __typename, which clients need.
	if r := off.ok(off.gql(adminKey, `{ __typename tenants { total __typename } }`, nil)); r.str("__typename") != "Query" || r.str("tenants.__typename") != "TenantConnection" {
		t.Fatalf("with introspection off: %s", r.Raw)
	}
}

func TestQueryLimits(t *testing.T) {
	h := newHarness(t, nil)
	invalid := func(name, query string) result {
		t.Helper()
		r := h.gql(adminKey, query, nil)
		if r.Status != 200 || len(r.Errors) == 0 || r.Data != nil {
			t.Fatalf("%s: got %d %.300s, want a refusal without data", name, r.Status, r.Raw)
		}
		for _, e := range r.Errors {
			if e.Extensions.Code != "invalid_query" || e.Extensions.RequestID == "" {
				t.Fatalf("%s: error shape: %.300s", name, r.Raw)
			}
		}
		return r
	}

	// Depth: MaxDepth levels are served, one more is not.
	nested := func(levels int) string { // a query levels+3 deep
		return `{ __schema { types { ` + strings.Repeat(`ofType { `, levels) + `name` + strings.Repeat(` }`, levels) + ` } } }`
	}
	h.ok(h.gql("", nested(graphqlapi.MaxDepth-3), nil))
	deep := invalid("too deep", nested(graphqlapi.MaxDepth-2))
	if !strings.Contains(deep.Errors[0].Message, "exceeds max depth") {
		t.Fatalf("depth error: %s", deep.Raw)
	}
	// Fragments do not hide depth.
	invalid("too deep through fragments", `{ __schema { types { ...A } } }
		fragment A on __Type { ofType { ofType { ofType { ofType { ofType { ...B } } } } } }
		fragment B on __Type { ofType { ofType { ofType { ofType { ofType { ofType { ofType { ofType { ofType { name } } } } } } } } } }`)
	invalid("fragment cycle", `{ __schema { types { ...A } } } fragment A on __Type { ofType { ...B } } fragment B on __Type { ofType { ...A } }`)

	// Length: a document over MaxQueryBytes is refused before it is parsed.
	pad := strings.Repeat(" ", graphqlapi.MaxQueryBytes)
	h.ok(h.gql(adminKey, `{ tenants { total } }`+pad[:len(pad)-len(`{ tenants { total } }`)], nil))
	long := invalid("too long", `{ tenants { total } }`+pad)
	if !strings.Contains(long.Errors[0].Message, "exceeds the maximum allowed query length") {
		t.Fatalf("length error: %s", long.Raw)
	}

	// Selections: fragments that multiply are refused, not expanded.
	var doc strings.Builder
	doc.WriteString(`{ tenants { ...F0 } }`)
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&doc, " fragment F%d on TenantConnection { ...F%d ...F%d }", i, i+1, i+1)
	}
	doc.WriteString(` fragment F12 on TenantConnection { total }`)
	many := h.gql(adminKey, doc.String(), nil)
	if many.Status != 200 || len(many.Errors) != 1 || !strings.Contains(many.Errors[0].Message, "too many selections") || many.at("tenants") != nil {
		t.Fatalf("exponential fragments: %d %.300s", many.Status, many.Raw)
	}

	// Other documents the engine refuses.
	invalid("syntax error", `{ tenants { total `)
	invalid("unknown field", `{ tenants { total passwordHash } }`)
	invalid("unknown argument", `{ tenants(everything: true) { total } }`)
	invalid("wrong argument type", `{ tenants(limit: "ten") { total } }`)
	invalid("missing required argument", `{ tenant { id } }`)
	invalid("no subscriptions", `subscription { tenants { total } }`)
	invalid("two anonymous operations", `{ tenants { total } } { me { roles } }`)
}

func TestOperationNameAndVariables(t *testing.T) {
	h := newHarness(t, nil)
	h.tenant("acme")
	send := func(body M) result {
		t.Helper()
		raw, _ := json.Marshal(body)
		return h.post(adminKey, "application/json", strings.NewReader(string(raw)))
	}
	const doc = `query One($limit: Int) { tenants(limit: $limit) { limit } } query Two { tenants { total } }`

	r := h.ok(send(M{"query": doc, "operationName": "One", "variables": M{"limit": 7}}))
	if r.num("tenants.limit") != 7 || r.at("tenants.total") != nil {
		t.Fatalf("operation One: %s", r.Raw)
	}
	if r := h.ok(send(M{"query": doc, "operationName": "Two"})); r.num("tenants.total") != 1 {
		t.Fatalf("operation Two: %s", r.Raw)
	}
	for name, body := range map[string]M{
		"no operation name":      {"query": doc},
		"unknown operation name": {"query": doc, "operationName": "Three"},
		"variable of wrong type": {"query": doc, "operationName": "One", "variables": M{"limit": "seven"}},
		"fractional Int":         {"query": doc, "operationName": "One", "variables": M{"limit": 7.5}},
		"Int beyond 32 bits":     {"query": doc, "operationName": "One", "variables": M{"limit": 1 << 40}},
	} {
		if r := send(body); r.Status != 200 || len(r.Errors) == 0 || r.Errors[0].Extensions.Code != "invalid_query" || r.at("tenants") != nil {
			t.Errorf("%s: got %d %s", name, r.Status, r.Raw)
		}
	}
}

func TestMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	const q = `{"query":"{ tenants { total } }"}`
	rejected := func(name string, r result, status int, code string) {
		t.Helper()
		if r.Status != status || len(r.Errors) != 1 || r.Errors[0].Extensions.Code != code || r.Errors[0].Extensions.RequestID == "" || r.Data != nil {
			t.Fatalf("%s: got %d %.300s, want %d %s", name, r.Status, r.Raw, status, code)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Fatalf("%s: content type %q", name, ct)
		}
	}
	post := func(body string) result { return h.post(adminKey, "application/json", strings.NewReader(body)) }

	h.ok(post(q))
	h.ok(h.post(adminKey, "application/json; charset=utf-8", strings.NewReader(q)))

	// Only JSON is read. A cross-site HTML form cannot send it.
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/graphql", "application/jsonx", "garbage/;;"} {
		rejected("content type "+ct, h.post(adminKey, ct, strings.NewReader(q)), 415, "unsupported_media_type")
	}

	for name, body := range map[string]string{
		"truncated":               `{"query":`,
		"empty":                   ``,
		"array (batch)":           `[` + q + `,` + q + `]`,
		"string":                  `"{ tenants { total } }"`,
		"two objects":             q + q,
		"query not a string":      `{"query":123}`,
		"variables not an object": `{"query":"{ tenants { total } }","variables":"x"}`,
		"deeply nested":           `{"query":"{ tenants { total } }","variables":` + strings.Repeat(`{"a":`, 100000) + "1" + strings.Repeat("}", 100000) + `}`,
	} {
		rejected(name, post(body), 400, "invalid_json")
	}
	for name, body := range map[string]string{
		"no query":       `{}`,
		"null query":     `{"query":null}`,
		"blank query":    `{"query":"  \n "}`,
		"only variables": `{"variables":{"a":1}}`,
	} {
		r := post(body)
		rejected(name, r, 400, "validation_failed")
		if r.Errors[0].Extensions.Details["query"] == "" {
			t.Fatalf("%s: details do not name the query: %s", name, r.Raw)
		}
	}

	// The body limit holds wherever the bulk is.
	big := strings.Repeat("x", graphqlapi.MaxBodyBytes)
	rejected("large variables", post(`{"query":"{ tenants { total } }","variables":{"a":"`+big+`"}}`), 413, "payload_too_large")
	rejected("large query", post(`{"query":"{ tenants { total } } #`+big+`"}`), 413, "payload_too_large")
	rejected("large unknown member", post(`{"junk":"`+big+`","query":"{ tenants { total } }"}`), 413, "payload_too_large")

	// Only POST is routed to the handler.
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		req, _ := http.NewRequest(method, h.srv.URL+"/graphql?query={tenants{total}}", nil)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 405 {
			t.Fatalf("%s /graphql: %d, want 405", method, res.StatusCode)
		}
	}
}

// Mounted wrongly (without a method in the pattern), the handler still
// serves POST only.
func TestHandlerRefusesOtherMethods(t *testing.T) {
	env := testutil.NewEnv(t, memory.New(), nil)
	api := httpapi.New(env.Svc, httpapi.Config{AdminKey: adminKey}, testutil.Logger())
	h, err := graphqlapi.NewHandler(api.Gate(), testutil.Logger(), graphqlapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "HEAD", "PUT", "DELETE", "OPTIONS"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/graphql?query={tenants{total}}", nil)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code != 405 || rec.Header().Get("Allow") != "POST" || !strings.Contains(rec.Body.String(), `"code":"method_not_allowed"`) || strings.Contains(rec.Body.String(), `"data"`) {
			t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
		}
	}
}

func TestErrorShape(t *testing.T) {
	h := newHarness(t, nil)
	tid, client := h.tenant("acme")
	_, access, _ := h.user(client, "ada@example.com")

	// A well-formed request whose execution fails is still HTTP 200. Fields
	// that succeed keep their data; a failed one is null and has an error.
	r := h.gql(access, `query($t: ID!) { me { user { email } } denied: users(tenantId: $t) { total } }`, M{"t": tid}, "X-Request-ID", "trace-123")
	if r.Status != 200 || r.str("me.user.email") != "ada@example.com" || r.at("denied") != nil || len(r.Errors) != 1 {
		t.Fatalf("partial result: %d %s", r.Status, r.Raw)
	}
	var body struct {
		Errors []map[string]json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal([]byte(r.Raw), &body); err != nil {
		t.Fatal(err)
	}
	e := body.Errors[0]
	if string(e["message"]) != `"you do not have permission to perform this action"` || string(e["path"]) != `["denied"]` ||
		string(e["extensions"]) != `{"code":"forbidden","request_id":"trace-123"}` || len(e) != 3 {
		t.Fatalf("error: %s", r.Raw)
	}
	if r.Header.Get("X-Request-ID") != "trace-123" {
		t.Fatalf("request ID header: %v", r.Header)
	}

	// Validation failures of the service carry per-field details.
	v := h.fails(h.gql(client, `mutation { register(email: "nope", password: "`+password+`") { id } }`, nil), "validation_failed")
	if v.Errors[0].Extensions.Details["email"] == "" || v.Errors[0].Message != "request validation failed" {
		t.Fatalf("validation error: %s", v.Raw)
	}
	// An error without details has no details member at all.
	if nf := h.gql(adminKey, `{ tenant(id: "nope") { id } }`, nil); strings.Contains(nf.Raw, "details") || nf.Errors[0].Extensions.Code != "not_found" {
		t.Fatalf("not found: %s", nf.Raw)
	}

	// A request ID is generated when the caller sends none, and it is the
	// one in the response header.
	gen := h.gql("", `{ me { roles } }`, nil)
	if id := gen.Errors[0].Extensions.RequestID; id == "" || id != gen.Header.Get("X-Request-ID") {
		t.Fatalf("generated request ID: %s / %v", gen.Raw, gen.Header)
	}

	// The response has the API's security headers and is never cached.
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
		"Referrer-Policy": "no-referrer", "Content-Type": "application/json; charset=utf-8",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if r.Header.Get("Set-Cookie") != "" {
		t.Error("the GraphQL endpoint set a cookie")
	}
}

func TestExtension(t *testing.T) {
	ext := graphqlapi.Extension()
	if ext.Name != "graphql" || ext.HTTP == nil || ext.Serve != nil {
		t.Fatalf("extension: %+v", ext)
	}
	env := testutil.NewEnv(t, memory.New(), nil)
	api := httpapi.New(env.Svc, httpapi.Config{AdminKey: adminKey}, testutil.Logger())
	deps := func(cfg config.Config) server.Deps {
		return server.Deps{Service: env.Svc, Gate: api.Gate(), Config: &cfg, Log: testutil.Logger(), Version: "test"}
	}

	// Switched off by configuration: nothing to mount.
	routes, err := ext.HTTP(deps(config.Config{GraphQLEnabled: false, GraphQLIntrospection: true}))
	if err != nil || routes != nil {
		t.Fatalf("disabled: %v %v", routes, err)
	}

	routes, err = ext.HTTP(deps(config.Config{GraphQLEnabled: true, GraphQLIntrospection: false}))
	if err != nil || len(routes) != 1 || routes["POST /graphql"] == nil {
		t.Fatalf("enabled: %v %v", routes, err)
	}
	for pattern, h := range routes {
		api.Mount(pattern, h)
	}
	srv := httptest.NewServer(api)
	defer srv.Close()
	h := &harness{t: t, env: env, srv: srv}
	if r := h.ok(h.gql(adminKey, `{ tenants { total } }`, nil)); r.num("tenants.total") != 0 {
		t.Fatalf("mounted extension: %s", r.Raw)
	}
	// KEYORA_GRAPHQL_INTROSPECTION reaches the handler.
	if r := h.gql("", `{ __schema { queryType { name } } }`, nil); r.at("__schema") != nil {
		t.Fatalf("introspection should be off: %s", r.Raw)
	}
	found := false
	for _, route := range api.Routes() {
		found = found || route == "POST /graphql"
	}
	if !found {
		t.Fatal("POST /graphql is not among the API's routes")
	}
}
