package graphqlapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

const (
	redirectURI = "https://app.example.com/callback"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

func challengeFor(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const authorizeMutation = `mutation($in: AuthorizeInput!) {
	authorize(input: $in) { code state redirectUri redirectTo expiresIn iss }
}`

const tokenMutation = `mutation($in: TokenInput!) {
	token(input: $in) { accessToken tokenType expiresIn refreshToken refreshExpiresIn sessionId idToken scope }
}`

// authorizeInput is an authorization request together with the user's
// credentials.
func authorizeInput(clientID string) M {
	return M{"clientId": clientID, "redirectUri": redirectURI, "responseType": "code", "state": "xyz-state", "scope": "profile",
		"codeChallenge": challengeFor(verifier), "codeChallengeMethod": "S256", "email": "ada@example.com", "password": password}
}

func exchange(clientID, code string) M {
	return M{"grantType": "AUTHORIZATION_CODE", "clientId": clientID, "code": code, "redirectUri": redirectURI, "codeVerifier": verifier}
}

// pkceSetup creates a tenant with a public SPA and a registered user. It
// returns the SPA's client ID and the tenant's confidential application.
func pkceSetup(t *testing.T) (h *harness, tenantID, clientID, backend string) {
	h = newHarness(t, nil)
	tenantID, backend = h.tenant("acme")
	spa := h.ok(h.gql(adminKey, `mutation($t: ID!, $uri: String!) {
		createApplication(tenantId: $t, input: {name: "Acme SPA", type: "public", redirectUris: [$uri], allowedOrigins: ["https://app.example.com"]}) {
			application { clientId }
		}
	}`, M{"t": tenantID, "uri": redirectURI}))
	h.ok(h.gql(backend, `mutation { register(email: "ada@example.com", password: "`+password+`") { id } }`, nil))
	return h, tenantID, spa.str("createApplication.application.clientId"), backend
}

// signIn obtains an authorization code for ada.
func signIn(t *testing.T, h *harness, clientID string) string {
	t.Helper()
	return h.ok(h.gql("", authorizeMutation, M{"in": authorizeInput(clientID)})).str("authorize.code")
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	h, tenantID, clientID, _ := pkceSetup(t)

	az := h.ok(h.gql("", authorizeMutation, M{"in": authorizeInput(clientID)}))
	code := az.str("authorize.code")
	if !strings.HasPrefix(code, "kyc_") || az.str("authorize.state") != "xyz-state" || az.str("authorize.iss") != "https://id.test" ||
		az.str("authorize.redirectUri") != redirectURI || az.num("authorize.expiresIn") != 60 {
		t.Fatalf("authorization: %s", az.Raw)
	}
	// redirectTo is the complete authorization response, ready to navigate to.
	to, err := url.Parse(az.str("authorize.redirectTo"))
	if err != nil || to.Scheme+"://"+to.Host+to.Path != redirectURI || to.Query().Get("code") != code ||
		to.Query().Get("state") != "xyz-state" || to.Query().Get("iss") != "https://id.test" {
		t.Fatalf("redirectTo: %q", az.str("authorize.redirectTo"))
	}
	// Headless: JSON only, never cached, and no cookie that could become an ambient credential.
	if !strings.HasPrefix(az.Header.Get("Content-Type"), "application/json") || az.Header.Get("Set-Cookie") != "" || az.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("authorization response headers: %v", az.Header)
	}

	tok := h.ok(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}))
	if tok.str("token.tokenType") != "Bearer" || tok.str("token.refreshToken") == "" || tok.str("token.scope") != "profile" ||
		tok.num("token.expiresIn") <= 0 || tok.num("token.refreshExpiresIn") <= 0 || tok.at("token.idToken") != nil {
		t.Fatalf("token response: %s", tok.Raw)
	}
	access := tok.str("token.accessToken")
	claims, err := jwt.Verify(access, h.env.Svc.Keys().JWKS().KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: clientID, Now: h.env.Clock.Now})
	if err != nil || claims.Email != "ada@example.com" || claims.TenantID != tenantID {
		t.Fatalf("access token: %v %+v", err, claims)
	}
	h.ok(h.gql(access, `{ me { user { id } } }`, nil))

	// The refresh grant works for a public client, rotates, and detects reuse.
	refresh := M{"in": M{"grantType": "REFRESH_TOKEN", "clientId": clientID, "refreshToken": tok.str("token.refreshToken")}}
	next := h.ok(h.gql("", tokenMutation, refresh))
	if next.str("token.refreshToken") == tok.str("token.refreshToken") {
		t.Fatalf("refresh grant did not rotate: %s", next.Raw)
	}
	// Like the REST token endpoint, every unusable grant is invalid_grant,
	// whatever the reason (here: reuse, which also revoked the session).
	h.fails(h.gql("", tokenMutation, refresh), "invalid_grant")
	h.fails(h.gql(next.str("token.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")

	audit := h.ok(h.gql(adminKey, `query($t: ID!) { auditEvents(tenantId: $t, type: "token.code_exchanged") { total } }`, M{"t": tenantID}))
	if audit.num("auditEvents.total") != 1 {
		t.Fatalf("code exchange was not audited: %s", audit.Raw)
	}
}

func TestPKCEVerifierIsEnforced(t *testing.T) {
	h, _, clientID, _ := pkceSetup(t)
	bad := func(name string, mod func(M)) {
		t.Helper()
		code := signIn(t, h, clientID)
		in := exchange(clientID, code)
		mod(in)
		if r := h.gql("", tokenMutation, M{"in": in}); len(r.Errors) != 1 || r.Errors[0].Extensions.Code != "invalid_grant" || r.at("token") != nil {
			t.Fatalf("%s: got %s, want invalid_grant", name, r.Raw)
		}
		// A failed attempt burns the code: the right verifier does not get a second chance.
		h.fails(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}), "invalid_grant")
	}
	bad("wrong verifier", func(in M) { in["codeVerifier"] = strings.Repeat("a", 43) })
	bad("missing verifier", func(in M) { delete(in, "codeVerifier") })
	bad("verifier too short", func(in M) { in["codeVerifier"] = "short" })
	bad("the challenge sent as the verifier", func(in M) { in["codeVerifier"] = challengeFor(verifier) })
	bad("different redirect URI", func(in M) { in["redirectUri"] = redirectURI + "/other" })
	bad("missing redirect URI", func(in M) { delete(in, "redirectUri") })

	for _, code := range []string{"", "kyc_never-issued", strings.Repeat("x", 5000)} {
		h.fails(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}), "invalid_grant")
	}
}

func TestAuthorizationCodeIsSingleUseAndShortLived(t *testing.T) {
	h, tenantID, clientID, _ := pkceSetup(t)

	code := signIn(t, h, clientID)
	tok := h.ok(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}))
	// Replay: refused, and the tokens already issued from the code are revoked.
	h.fails(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}), "invalid_grant")
	h.fails(h.gql(tok.str("token.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")
	audit := h.ok(h.gql(adminKey, `query($t: ID!) { auditEvents(tenantId: $t, type: "code.reuse_detected") { total } }`, M{"t": tenantID}))
	if audit.num("auditEvents.total") != 1 {
		t.Fatalf("code reuse was not audited: %s", audit.Raw)
	}

	code = signIn(t, h, clientID)
	h.env.Clock.Advance(61 * time.Second)
	h.fails(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}), "invalid_grant")

	// One document cannot redeem a code twice either: the fields of a
	// mutation run in order, and the second one finds the code used.
	code = signIn(t, h, clientID)
	r := h.gql("", `mutation($in: TokenInput!) { a: token(input: $in) { accessToken } b: token(input: $in) { accessToken } }`,
		M{"in": exchange(clientID, code)})
	if r.at("a.accessToken") == nil || r.at("b") != nil || r.codeAt("b") != "invalid_grant" {
		t.Fatalf("double redemption in one document: %s", r.Raw)
	}
}

func TestAuthorizationCodeIsBoundToItsClient(t *testing.T) {
	h, _, spa, backend := pkceSetup(t)
	backendID, _, _ := strings.Cut(backend, ":")

	// A code issued to the SPA cannot be redeemed by another application,
	// even one that authenticates correctly.
	code := signIn(t, h, spa)
	in := exchange(backendID, code)
	h.fails(h.gql(backend, tokenMutation, M{"in": in}), "invalid_grant")
	h.fails(h.gql("", tokenMutation, M{"in": exchange(spa, code)}), "invalid_grant")
}

func TestAuthorizeRequestIsValidatedByTheService(t *testing.T) {
	h, _, clientID, _ := pkceSetup(t)
	try := func(want string, mod func(M), headers ...string) result {
		t.Helper()
		in := authorizeInput(clientID)
		mod(in)
		return h.fails(h.gql("", authorizeMutation, M{"in": in}, headers...), want)
	}
	try("invalid_client", func(in M) { in["clientId"] = "kyc_unknown" })
	try("invalid_redirect_uri", func(in M) { in["redirectUri"] = "https://evil.example/callback" })
	try("unsupported_response_type", func(in M) { in["responseType"] = "token" })
	try("invalid_request", func(in M) { in["codeChallengeMethod"] = "plain" })
	try("invalid_request", func(in M) { in["codeChallenge"] = "" })

	// A browser may only call from an origin registered on the application.
	try("origin_not_allowed", func(M) {}, "Origin", "https://evil.example")
	h.ok(h.gql("", authorizeMutation, M{"in": authorizeInput(clientID)}, "Origin", "https://app.example.com"))

	// Wrong password and unknown user are indistinguishable, and nothing is echoed.
	wrong := try("invalid_credentials", func(in M) { in["password"] = "wrong password" })
	unknown := try("invalid_credentials", func(in M) { in["email"], in["password"] = "nobody@example.com", "wrong password" })
	if wrong.Errors[0].Message != unknown.Errors[0].Message || strings.Contains(wrong.Raw, "wrong password") {
		t.Fatalf("wrong password vs unknown user: %s / %s", wrong.Raw, unknown.Raw)
	}
	// The field shares the account lockout with login (the limit is 3 in tests).
	try("invalid_credentials", func(in M) { in["password"] = "wrong again" })
	try("invalid_credentials", func(in M) { in["password"] = "and again" })
	try("account_locked", func(M) {})
}

func TestOpenIDConnect(t *testing.T) {
	h, _, clientID, _ := pkceSetup(t)
	in := authorizeInput(clientID)
	in["scope"], in["nonce"] = "openid email profile", "n-0S6_WzA2Mj"
	code := h.ok(h.gql("", authorizeMutation, M{"in": in})).str("authorize.code")
	tok := h.ok(h.gql("", tokenMutation, M{"in": exchange(clientID, code)}))
	idToken, access := tok.str("token.idToken"), tok.str("token.accessToken")

	id, err := jwt.Verify(idToken, h.env.Svc.Keys().JWKS().KeyFunc(), jwt.Validation{Issuer: "https://id.test", Audience: clientID, Now: h.env.Clock.Now})
	if err != nil || id.Nonce != "n-0S6_WzA2Mj" || id.Email != "ada@example.com" || id.TokenUse != "id" {
		t.Fatalf("ID token: %v %+v", err, id)
	}

	// An ID token is not an API credential: not for self-service, not for
	// management, not for userinfo, not for logout.
	for _, q := range []string{
		`{ me { user { id } } }`,
		`{ mySessions { total } }`,
		`{ userinfo { sub } }`,
		`{ tenants { total } }`,
		`mutation { updateMe(name: "x") { id } }`,
		`mutation { logout }`,
	} {
		h.fails(h.gql(idToken, q, nil), "invalid_token")
	}

	info := h.ok(h.gql(access, `{ userinfo { sub email emailVerified name } }`, nil))
	if info.str("userinfo.sub") != id.Subject || info.str("userinfo.email") != "ada@example.com" || info.at("userinfo.emailVerified") != false {
		t.Fatalf("userinfo: %s", info.Raw)
	}
	h.fails(h.gql("", `{ userinfo { sub } }`, nil), "unauthenticated")
}

func TestClientCredentialsGrant(t *testing.T) {
	h, _, spa, backend := pkceSetup(t)
	id, secret, _ := strings.Cut(backend, ":")
	grant := M{"in": M{"grantType": "CLIENT_CREDENTIALS"}}

	tok := h.ok(h.gql(backend, tokenMutation, grant))
	if tok.str("token.tokenType") != "Bearer" || tok.str("token.accessToken") == "" || tok.at("token.refreshToken") != nil ||
		tok.at("token.sessionId") != nil || tok.at("token.refreshExpiresIn") != nil {
		t.Fatalf("token response: %s", tok.Raw)
	}
	h.ok(h.gql("", tokenMutation, M{"in": M{"grantType": "CLIENT_CREDENTIALS", "clientId": id, "clientSecret": secret}}))
	h.fails(h.gql("", tokenMutation, M{"in": M{"grantType": "CLIENT_CREDENTIALS", "clientId": id, "clientSecret": "nope"}}), "invalid_client")
	h.fails(h.gql("", tokenMutation, grant), "invalid_client")
	// A public application has no secret and cannot use this grant.
	h.fails(h.gql("", tokenMutation, M{"in": M{"grantType": "CLIENT_CREDENTIALS", "clientId": spa}}), "invalid_client")

	// The token identifies the application, not a user.
	h.fails(h.gql(tok.str("token.accessToken"), `{ me { user { id } } }`, nil), "invalid_token")
	in := h.ok(h.gql(backend, `query($token: String!) { introspectToken(token: $token) { active subject email } }`, M{"token": tok.str("token.accessToken")}))
	if in.at("introspectToken.active") != true || in.str("introspectToken.subject") != id || in.at("introspectToken.email") != nil {
		t.Fatalf("introspection of a client credentials token: %s", in.Raw)
	}

	// The grant type is an enum: anything else never reaches a resolver.
	r := h.gql(backend, tokenMutation, M{"in": M{"grantType": "PASSWORD"}})
	if len(r.Errors) == 0 || r.Errors[0].Extensions.Code != "invalid_query" || r.at("token") != nil {
		t.Fatalf("unsupported grant: %s", r.Raw)
	}
}
