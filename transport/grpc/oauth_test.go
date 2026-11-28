package grpcapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/rabbicse/keyora/jwt"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

const (
	redirectURI = "https://app.example.com/callback"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

func challengeFor(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceSetup creates a tenant with a confidential application, a public
// single-page application and a registered user. It returns the tenant ID,
// the confidential application and the public application's client ID.
func pkceSetup(t *testing.T) (h *harness, tenantID string, backend client, spa string) {
	h = newHarness(t, nil)
	tenantID, backend = h.tenant("acme")
	app := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{
		TenantId: tenantID, Name: "Acme SPA", Type: "public",
		RedirectUris: []string{redirectURI}, AllowedOrigins: []string{"https://app.example.com"},
	}))(t)
	must(h.auth.Register(h.basic(backend), &keyorapb.RegisterRequest{Email: "ada@example.com", Password: password, Name: "Ada"}))(t)
	return h, tenantID, backend, app.GetApplication().GetClientId()
}

// authorizeRequest is an authorization request together with the user's
// credentials.
func authorizeRequest(clientID string) *keyorapb.AuthorizeRequest {
	return &keyorapb.AuthorizeRequest{
		ClientId: clientID, RedirectUri: redirectURI, ResponseType: "code", State: "xyz-state", Scope: "profile",
		CodeChallenge: challengeFor(verifier), CodeChallengeMethod: "S256",
		Email: "ada@example.com", Password: password,
	}
}

func exchange(clientID, code string) *keyorapb.TokenRequest {
	return &keyorapb.TokenRequest{GrantType: "authorization_code", ClientId: clientID, Code: code,
		RedirectUri: redirectURI, CodeVerifier: verifier}
}

// signIn obtains an authorization code for ada.
func signIn(t *testing.T, h *harness, clientID string) string {
	t.Helper()
	code := must(h.oauth.Authorize(h.ctx(), authorizeRequest(clientID)))(t).GetCode()
	if code == "" {
		t.Fatal("authorization succeeded without a code")
	}
	return code
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	h, tid, _, spa := pkceSetup(t)

	res := must(h.oauth.Authorize(h.ctx("origin", "https://app.example.com"), authorizeRequest(spa)))(t)
	if res.GetCode() == "" || res.GetState() != "xyz-state" || res.GetRedirectUri() != redirectURI ||
		res.GetExpiresIn() != 60 || res.GetIss() != "https://id.test" {
		t.Fatalf("authorization response: %v", res)
	}
	to, err := url.Parse(res.GetRedirectTo())
	if err != nil || !strings.HasPrefix(res.GetRedirectTo(), redirectURI+"?") || to.Query().Get("code") != res.GetCode() ||
		to.Query().Get("state") != "xyz-state" || to.Query().Get("iss") != "https://id.test" {
		t.Fatalf("redirect_to: %q", res.GetRedirectTo())
	}

	tok := must(h.oauth.Token(h.ctx(), exchange(spa, res.GetCode())))(t)
	if tok.GetScope() != "profile" || tok.GetTokens().GetTokenType() != "Bearer" || tok.GetTokens().GetRefreshToken() == "" ||
		tok.GetTokens().GetIdToken() != "" {
		t.Fatalf("token response: %v", tok)
	}
	me := must(h.account.GetMe(h.bearer(tok.GetTokens().GetAccessToken()), &keyorapb.GetMeRequest{}))(t)
	if me.GetUser().GetEmail() != "ada@example.com" || me.GetUser().GetTenantId() != tid {
		t.Fatalf("the access token is not ada's: %v", me)
	}

	// The refresh_token grant rotates the token like AuthService.Refresh.
	next := must(h.oauth.Token(h.ctx(), &keyorapb.TokenRequest{GrantType: "refresh_token", ClientId: spa,
		RefreshToken: tok.GetTokens().GetRefreshToken()}))(t)
	if next.GetTokens().GetSessionId() != tok.GetTokens().GetSessionId() || next.GetTokens().GetRefreshToken() == tok.GetTokens().GetRefreshToken() {
		t.Fatalf("refresh grant: %v", next)
	}
	_, unknown := h.oauth.Token(h.ctx(), &keyorapb.TokenRequest{GrantType: "refresh_token", ClientId: spa, RefreshToken: "kyr_unknown"})
	expect(t, unknown, codes.InvalidArgument, "invalid_grant")

	// The Token RPC gives no hint about why a grant is unusable: a reused
	// refresh token is answered exactly like an unknown one (and still
	// revokes the session), while AuthService.Refresh names the reason.
	_, reused := h.oauth.Token(h.ctx(), &keyorapb.TokenRequest{GrantType: "refresh_token", ClientId: spa,
		RefreshToken: tok.GetTokens().GetRefreshToken()})
	md := expect(t, reused, codes.InvalidArgument, "invalid_grant")
	if status.Convert(reused).Message() != status.Convert(unknown).Message() || len(md) != 1 || md["request_id"] == "" {
		t.Fatalf("a reused refresh token is distinguishable from an unknown one: %v (%v) vs %v", reused, md, unknown)
	}
	_, err = h.account.GetMe(h.bearer(next.GetTokens().GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.auth.Refresh(h.ctx(), &keyorapb.RefreshRequest{ClientId: spa, RefreshToken: tok.GetTokens().GetRefreshToken()})
	expect(t, err, codes.Unauthenticated, "refresh_token_reused")
}

func TestPKCEVerifierIsEnforced(t *testing.T) {
	h, _, _, spa := pkceSetup(t)
	for name, v := range map[string]string{
		"wrong":     strings.Repeat("v", 43),
		"missing":   "",
		"too short": "abc",
		"challenge": challengeFor(verifier), // the challenge itself is not the proof
	} {
		t.Run(name, func(t *testing.T) {
			code := signIn(t, h, spa)
			req := exchange(spa, code)
			req.CodeVerifier = v
			_, err := h.oauth.Token(h.ctx(), req)
			expect(t, err, codes.InvalidArgument, "invalid_grant")
			// The code is spent: the right verifier does not get a second try.
			_, err = h.oauth.Token(h.ctx(), exchange(spa, code))
			expect(t, err, codes.InvalidArgument, "invalid_grant")
		})
	}
}

func TestAuthorizationCodeIsSingleUseAndShortLived(t *testing.T) {
	h, _, _, spa := pkceSetup(t)

	code := signIn(t, h, spa)
	tok := must(h.oauth.Token(h.ctx(), exchange(spa, code)))(t).GetTokens()
	must(h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{}))(t)
	// Replaying the code fails and revokes the session it opened.
	_, err := h.oauth.Token(h.ctx(), exchange(spa, code))
	expect(t, err, codes.InvalidArgument, "invalid_grant")
	_, err = h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")

	code = signIn(t, h, spa)
	h.env.Clock.Advance(61 * time.Second)
	_, err = h.oauth.Token(h.ctx(), exchange(spa, code))
	expect(t, err, codes.InvalidArgument, "invalid_grant")

	// The redirect URI of the token request must be the one the code was issued for.
	req := exchange(spa, signIn(t, h, spa))
	req.RedirectUri = "https://app.example.com/other"
	_, err = h.oauth.Token(h.ctx(), req)
	expect(t, err, codes.InvalidArgument, "invalid_grant")
	_, err = h.oauth.Token(h.ctx(), exchange(spa, "kyc_unknown"))
	expect(t, err, codes.InvalidArgument, "invalid_grant")
}

func TestAuthorizationCodeIsBoundToItsClient(t *testing.T) {
	h, tid, backend, spa := pkceSetup(t)
	other := must(h.apps.CreateApplication(h.root(), &keyorapb.CreateApplicationRequest{TenantId: tid, Name: "Other SPA", Type: "public",
		RedirectUris: []string{redirectURI}}))(t).GetApplication().GetClientId()

	_, err := h.oauth.Token(h.ctx(), exchange(other, signIn(t, h, spa)))
	expect(t, err, codes.InvalidArgument, "invalid_grant")
	_, err = h.oauth.Token(h.basic(backend), exchange("", signIn(t, h, spa)))
	expect(t, err, codes.InvalidArgument, "invalid_grant")

	// A confidential application must authenticate to redeem its own code.
	must(h.apps.UpdateApplication(h.root(), &keyorapb.UpdateApplicationRequest{TenantId: tid, Id: appID(t, h, tid, backend.id),
		RedirectUris: &keyorapb.StringList{Values: []string{redirectURI}}}))(t)
	_, err = h.oauth.Token(h.ctx(), exchange(backend.id, signIn(t, h, backend.id)))
	expect(t, err, codes.Unauthenticated, "invalid_client")
	must(h.oauth.Token(h.basic(backend), exchange("", signIn(t, h, backend.id))))(t)
}

// appID looks up an application's id by its client_id.
func appID(t *testing.T, h *harness, tenantID, clientID string) string {
	t.Helper()
	for _, a := range must(h.apps.ListApplications(h.root(), &keyorapb.ListApplicationsRequest{TenantId: tenantID, Limit: 100}))(t).GetApplications() {
		if a.GetClientId() == clientID {
			return a.GetId()
		}
	}
	t.Fatalf("no application with client_id %s", clientID)
	return ""
}

func TestAuthorizeRequestValidation(t *testing.T) {
	h, tid, _, spa := pkceSetup(t)
	cases := []struct {
		name   string
		change func(*keyorapb.AuthorizeRequest)
		code   codes.Code
		reason string
	}{
		{"unknown client", func(r *keyorapb.AuthorizeRequest) { r.ClientId = "app_unknown" }, codes.InvalidArgument, "invalid_client"},
		{"no client", func(r *keyorapb.AuthorizeRequest) { r.ClientId = "" }, codes.InvalidArgument, "invalid_client"},
		{"unregistered redirect", func(r *keyorapb.AuthorizeRequest) { r.RedirectUri = "https://evil.example/cb" }, codes.InvalidArgument, "invalid_redirect_uri"},
		{"redirect prefix", func(r *keyorapb.AuthorizeRequest) { r.RedirectUri = redirectURI + "/more" }, codes.InvalidArgument, "invalid_redirect_uri"},
		{"implicit flow", func(r *keyorapb.AuthorizeRequest) { r.ResponseType = "token" }, codes.InvalidArgument, "unsupported_response_type"},
		{"no challenge", func(r *keyorapb.AuthorizeRequest) { r.CodeChallenge = "" }, codes.InvalidArgument, "invalid_request"},
		{"plain method", func(r *keyorapb.AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, codes.InvalidArgument, "invalid_request"},
		{"malformed challenge", func(r *keyorapb.AuthorizeRequest) { r.CodeChallenge = "short" }, codes.InvalidArgument, "invalid_request"},
		{"oversized state", func(r *keyorapb.AuthorizeRequest) { r.State = strings.Repeat("s", 513) }, codes.InvalidArgument, "invalid_request"},
		{"wrong password", func(r *keyorapb.AuthorizeRequest) { r.Password = "not the password" }, codes.Unauthenticated, "invalid_credentials"},
		{"unknown user", func(r *keyorapb.AuthorizeRequest) { r.Email = "nobody@example.com" }, codes.Unauthenticated, "invalid_credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := authorizeRequest(spa)
			tc.change(req)
			res, err := h.oauth.Authorize(h.ctx(), req)
			expect(t, err, tc.code, tc.reason)
			if res.GetCode() != "" {
				t.Fatal("a code was issued for a refused request")
			}
		})
	}

	// response_type defaults to "code".
	req := authorizeRequest(spa)
	req.ResponseType = ""
	must(h.oauth.Authorize(h.ctx(), req))(t)

	// A page on another site cannot use a visitor's browser to try passwords.
	_, err := h.oauth.Authorize(h.ctx("origin", "https://evil.example"), authorizeRequest(spa))
	expect(t, err, codes.PermissionDenied, "origin_not_allowed")

	// A disabled application cannot start the flow.
	disabled := "disabled"
	must(h.apps.UpdateApplication(h.root(), &keyorapb.UpdateApplicationRequest{TenantId: tid, Id: appID(t, h, tid, spa), Status: &disabled}))(t)
	_, err = h.oauth.Authorize(h.ctx(), authorizeRequest(spa))
	expect(t, err, codes.InvalidArgument, "invalid_client")
}

func TestClientCredentialsGrant(t *testing.T) {
	h, _, backend, spa := pkceSetup(t)
	grant := &keyorapb.TokenRequest{GrantType: "client_credentials"}

	tok := must(h.oauth.Token(h.basic(backend), grant))(t).GetTokens()
	if tok.GetTokenType() != "Bearer" || tok.GetAccessToken() == "" || tok.GetRefreshToken() != "" || tok.GetSessionId() != "" {
		t.Fatalf("token response: %v", tok)
	}
	must(h.oauth.Token(h.ctx(), &keyorapb.TokenRequest{GrantType: "client_credentials", ClientId: backend.id, ClientSecret: backend.secret}))(t)
	if in := must(h.auth.Introspect(h.basic(backend), &keyorapb.IntrospectRequest{Token: tok.GetAccessToken()}))(t); !in.GetActive() ||
		in.GetSubject() != backend.id || in.GetSessionId() != "" {
		t.Fatalf("introspecting an application token: %v", in)
	}
	// An application token has no user behind it.
	_, err := h.account.GetMe(h.bearer(tok.GetAccessToken()), &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")

	for name, tc := range map[string]struct {
		req    *keyorapb.TokenRequest
		code   codes.Code
		reason string
	}{
		"bad secret":     {&keyorapb.TokenRequest{GrantType: "client_credentials", ClientId: backend.id, ClientSecret: "nope"}, codes.Unauthenticated, "invalid_client"},
		"public client":  {&keyorapb.TokenRequest{GrantType: "client_credentials", ClientId: spa}, codes.Unauthenticated, "invalid_client"},
		"no client":      {grant, codes.Unauthenticated, "invalid_client"},
		"password grant": {&keyorapb.TokenRequest{GrantType: "password", ClientId: backend.id, ClientSecret: backend.secret}, codes.InvalidArgument, "unsupported_grant_type"},
		"no grant type":  {&keyorapb.TokenRequest{ClientId: backend.id, ClientSecret: backend.secret}, codes.InvalidArgument, "unsupported_grant_type"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.oauth.Token(h.ctx(), tc.req)
			expect(t, err, tc.code, tc.reason)
		})
	}
}

func TestOpenIDConnect(t *testing.T) {
	h, _, _, spa := pkceSetup(t)
	req := authorizeRequest(spa)
	req.Scope, req.Nonce = "openid email profile", "n-0S6_WzA2Mj"
	tok := must(h.oauth.Token(h.ctx(), exchange(spa, must(h.oauth.Authorize(h.ctx(), req))(t).GetCode())))(t).GetTokens()
	if tok.GetIdToken() == "" {
		t.Fatalf("token response without id_token: %v", tok)
	}
	id, err := jwt.Verify(tok.GetIdToken(), h.env.Svc.Keys().PublicKey, jwt.Validation{Issuer: "https://id.test", Audience: spa, Now: h.env.Clock.Now})
	if err != nil {
		t.Fatalf("ID token does not verify: %v", err)
	}
	if id.Nonce != "n-0S6_WzA2Mj" || id.Email != "ada@example.com" || id.TokenUse != "id" || id.Subject == "" {
		t.Fatalf("ID token claims: %+v", id)
	}

	// An ID token is not an API credential, on any service.
	idToken := h.bearer(tok.GetIdToken())
	_, err = h.account.GetMe(idToken, &keyorapb.GetMeRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.oauth.UserInfo(idToken, &keyorapb.UserInfoRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.auth.Logout(idToken, &keyorapb.LogoutRequest{})
	expect(t, err, codes.Unauthenticated, "invalid_token")
	_, err = h.users.ListUsers(idToken, &keyorapb.ListUsersRequest{TenantId: id.TenantID})
	expect(t, err, codes.Unauthenticated, "invalid_token")

	info := must(h.oauth.UserInfo(h.bearer(tok.GetAccessToken()), &keyorapb.UserInfoRequest{}))(t)
	want := &keyorapb.UserInfoResponse{Subject: id.Subject, Email: "ada@example.com", Name: "Ada"}
	if !proto.Equal(info, want) {
		t.Fatalf("userinfo: got %v, want %v", info, want)
	}
	_, err = h.oauth.UserInfo(h.ctx(), &keyorapb.UserInfoRequest{})
	expect(t, err, codes.Unauthenticated, "unauthenticated")

	// No openid scope, no ID token.
	if tok := must(h.oauth.Token(h.ctx(), exchange(spa, signIn(t, h, spa))))(t).GetTokens(); tok.GetIdToken() != "" {
		t.Fatal("ID token issued without the openid scope")
	}
}
