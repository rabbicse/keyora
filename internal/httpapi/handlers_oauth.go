package httpapi

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
)

// This file implements the OAuth 2.0 endpoints:
//
//   - the authorization endpoint with Keyora's hosted sign-in page
//     (authorization code flow, RFC 6749 section 4.1, with mandatory PKCE,
//     RFC 7636);
//   - the token endpoint (authorization_code, refresh_token and
//     client_credentials grants);
//   - authorization server metadata (RFC 8414).
//
// They speak the RFCs' wire formats rather than the Keyora envelope so that
// standard OAuth client libraries work unchanged.

const csrfCookie = "keyora_csrf"

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in</title>
<style nonce="{{.Nonce}}">
:root { color-scheme: light dark; --bg:#f4f5f7; --card:#fff; --fg:#16181d; --muted:#5d6472; --line:#d5d9e0; --accent:#2f5bea; --err:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1115; --card:#181b21; --fg:#eceef2; --muted:#9aa2b1; --line:#2c313a; --accent:#7c9cff; --err:#ff8a80; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px; background:var(--bg); color:var(--fg);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:28px; }
.logo { display:block; margin:0 0 18px; }
h1 { font-size:1.35rem; margin:0 0 4px; }
p { margin:0 0 20px; color:var(--muted); }
label { display:block; font-size:.9rem; margin:14px 0 6px; }
input { width:100%; padding:10px 12px; font:inherit; color:inherit; background:transparent; border:1px solid var(--line); border-radius:8px; }
input:focus-visible, button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
button { width:100%; margin-top:22px; padding:11px; font:inherit; font-weight:600; color:#fff; background:var(--accent); border:0; border-radius:8px; cursor:pointer; }
@media (prefers-color-scheme: dark) { button { color:#0f1115; } }
.error { margin:0 0 4px; padding:10px 12px; border:1px solid var(--err); border-radius:8px; color:var(--err); }
</style>
</head>
<body>
<main>
<svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="44" height="44" role="img" aria-label="Keyora">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3B6BFF"/><stop offset="1" stop-color="#7A3CF0"/></linearGradient></defs>
<rect width="96" height="96" rx="22" fill="url(#g)"/>
<circle cx="33" cy="48" r="13" fill="none" stroke="#fff" stroke-width="7"/>
<path d="M46 48H60M60 48 76 30M60 48H78M60 48 76 66" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="33" cy="48" r="3.5" fill="#fff"/>
</svg>
<h1>Sign in</h1>
<p>to continue to <strong>{{.AppName}}</strong></p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<form method="post" action="/api/v1/oauth/authorize" autocomplete="on">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="client_id" value="{{.Req.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.Req.RedirectURI}}">
<input type="hidden" name="state" value="{{.Req.State}}">
<input type="hidden" name="scope" value="{{.Req.Scope}}">
<input type="hidden" name="nonce" value="{{.Req.Nonce}}">
<input type="hidden" name="code_challenge" value="{{.Req.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.Req.CodeChallengeMethod}}">
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="username" required autofocus value="{{.Email}}">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>
`))

var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Sign-in request not valid</title></head>
<body><h1>This sign-in request is not valid</h1><p>{{.}}</p>
<p>Return to the application and try again. If the problem continues, contact its developer.</p></body></html>
`))

type loginView struct {
	Nonce   string
	CSRF    string
	AppName string
	Email   string
	Error   string
	Req     service.AuthorizeRequest
}

func authorizeRequestFrom(v url.Values) service.AuthorizeRequest {
	return service.AuthorizeRequest{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), ResponseType: v.Get("response_type"),
		State: v.Get("state"), Scope: v.Get("scope"),
		CodeChallenge: v.Get("code_challenge"), CodeChallengeMethod: v.Get("code_challenge_method"),
		Nonce: v.Get("nonce"),
	}
}

func htmlHeaders(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	csp := "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
	if nonce != "" {
		csp += "; style-src 'nonce-" + nonce + "'"
	}
	w.Header().Set("Content-Security-Policy", csp)
}

// authorizeError shows an error on Keyora itself. It is used whenever the
// client or redirect URI could not be validated, because redirecting there
// would turn Keyora into an open redirector.
func authorizeError(w http.ResponseWriter, status int, message string) error {
	htmlHeaders(w, "")
	w.WriteHeader(status)
	return errorPage.Execute(w, message)
}

// redirectBack sends the browser to the (already validated) redirect URI. The
// "iss" parameter (RFC 9207) lets clients that talk to several authorization
// servers detect mix-up attacks.
func (a *API) redirectBack(w http.ResponseWriter, r *http.Request, req service.AuthorizeRequest, params url.Values) error {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return authorizeError(w, http.StatusBadRequest, "The redirect URI is malformed.")
	}
	q := u.Query()
	for k := range params {
		q.Set(k, params.Get(k))
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", a.svc.Issuer())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

// prepare validates the client and request shared by GET and POST. done is
// true when a response has already been written.
func (a *API) prepareAuthorize(w http.ResponseWriter, r *http.Request, req service.AuthorizeRequest) (app *domain.Application, done bool, err error) {
	app, err = a.svc.AuthorizeClient(r.Context(), req)
	switch {
	case errors.Is(err, domain.ErrInvalidClient):
		return nil, true, authorizeError(w, http.StatusBadRequest, "The application is unknown or disabled (client_id).")
	case errors.Is(err, domain.ErrInvalidRedirectURI):
		return nil, true, authorizeError(w, http.StatusBadRequest, "The redirect URI is not registered for this application.")
	case err != nil:
		return nil, true, err
	}
	if code, desc := service.ValidateAuthorizeRequest(req); code != "" {
		return nil, true, a.redirectBack(w, r, req, url.Values{"error": {code}, "error_description": {desc}})
	}
	return app, false, nil
}

func (a *API) renderLogin(w http.ResponseWriter, status int, view loginView) error {
	view.Nonce = security.NewToken("")
	view.CSRF = security.NewToken("")
	// Double-submit token: the form is only accepted with the cookie set by
	// this response, so another site cannot post credentials into this page
	// to sign a victim in as the attacker (login CSRF).
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: view.CSRF, Path: "/api/v1/oauth", MaxAge: 600,
		HttpOnly: true, Secure: a.cfg.HSTS, SameSite: http.SameSiteStrictMode})
	htmlHeaders(w, view.Nonce)
	w.WriteHeader(status)
	return loginPage.Execute(w, view)
}

func (a *API) authorizePage(w http.ResponseWriter, r *http.Request) error {
	req := authorizeRequestFrom(r.URL.Query())
	app, done, err := a.prepareAuthorize(w, r, req)
	if done {
		return err
	}
	return a.renderLogin(w, http.StatusOK, loginView{AppName: app.Name, Req: req})
}

func (a *API) authorizeSubmit(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return authorizeError(w, http.StatusBadRequest, "The form could not be read.")
	}
	req := authorizeRequestFrom(r.PostForm)
	app, done, err := a.prepareAuthorize(w, r, req)
	if done {
		return err
	}
	cookie, cerr := r.Cookie(csrfCookie)
	if cerr != nil || cookie.Value == "" || !security.ConstantTimeEqual(cookie.Value, r.PostForm.Get("csrf_token")) {
		return a.renderLogin(w, http.StatusForbidden, loginView{AppName: app.Name, Req: req, Email: r.PostForm.Get("email"),
			Error: "Your sign-in page expired. Please try again."})
	}
	code, err := a.svc.Authorize(r.Context(), app, req, r.PostForm.Get("email"), r.PostForm.Get("password"), metaFrom(r))
	if err != nil {
		status, msg := http.StatusInternalServerError, "Something went wrong. Please try again."
		var de *domain.Error
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			status, msg = http.StatusUnauthorized, "Incorrect email or password."
		case errors.Is(err, domain.ErrAccountLocked):
			status, msg = http.StatusLocked, "Too many failed attempts. Please wait a while and try again."
		case errors.Is(err, domain.ErrAccountDisabled):
			status, msg = http.StatusForbidden, "This account is disabled."
		case errors.Is(err, domain.ErrEmailNotVerified):
			status, msg = http.StatusForbidden, "Please verify your email address before signing in."
		case !errors.As(err, &de):
			a.log.Error("authorization failed", "request_id", requestID(r), "error", err)
		}
		return a.renderLogin(w, status, loginView{AppName: app.Name, Req: req, Email: r.PostForm.Get("email"), Error: msg})
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Path: "/api/v1/oauth", MaxAge: -1, HttpOnly: true, Secure: a.cfg.HSTS, SameSite: http.SameSiteStrictMode})
	return a.redirectBack(w, r, req, url.Values{"code": {code}})
}

// userinfo is the OpenID Connect userinfo endpoint (OIDC Core section 5.3).
func (a *API) userinfo(w http.ResponseWriter, r *http.Request) error {
	p, _, err := a.user(r)
	if err != nil {
		return err
	}
	info, err := a.svc.UserInfo(r.Context(), p)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, info)
	return nil
}

// oidcDiscovery is the OpenID Provider configuration document. It lists only
// what Keyora implements: the authorization code flow, RS256 ID tokens, and
// the openid, email and profile scopes.
func (a *API) oidcDiscovery(w http.ResponseWriter, _ *http.Request) error {
	iss := a.svc.Issuer()
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/api/v1/oauth/authorize",
		"token_endpoint":                                 iss + "/api/v1/oauth/token",
		"userinfo_endpoint":                              iss + "/api/v1/oauth/userinfo",
		"jwks_uri":                                       iss + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"scopes_supported":                               []string{"openid", "email", "profile"},
		"claims_supported":                               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "email", "email_verified", "name"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"authorization_response_iss_parameter_supported": true,
	})
	return nil
}

func (a *API) oauthMetadata(w http.ResponseWriter, _ *http.Request) error {
	iss := a.svc.Issuer()
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/api/v1/oauth/authorize",
		"token_endpoint":                                 iss + "/api/v1/oauth/token",
		"jwks_uri":                                       iss + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"authorization_response_iss_parameter_supported": true,
	})
	return nil
}

type oauthTokenResponse struct {
	*service.Tokens
	Scope string `json:"scope,omitempty"`
}

// oauthToken is the OAuth 2.0 token endpoint (RFC 6749 section 3.2).
func (a *API) oauthToken(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Pragma", "no-cache")
	fail := func(status int, code, desc string) error {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="keyora"`)
		}
		writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return fail(http.StatusBadRequest, "invalid_request", "body must be application/x-www-form-urlencoded")
	}
	form := r.PostForm
	grant := form.Get("grant_type")
	switch grant {
	case "authorization_code", "refresh_token", "client_credentials":
	default:
		return fail(http.StatusBadRequest, "unsupported_grant_type", "supported grants: authorization_code, refresh_token, client_credentials")
	}
	// Confidential applications authenticate with their secret; public ones
	// are identified by client_id and protected by PKCE.
	app, err := a.client(r, form.Get("client_id"), form.Get("client_secret"), grant == "client_credentials")
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) {
			return fail(http.StatusUnauthorized, "invalid_client", "client authentication failed")
		}
		return err
	}

	var tokens *service.Tokens
	scope := ""
	switch grant {
	case "authorization_code":
		tokens, scope, err = a.svc.ExchangeCode(r.Context(), app, form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier"), metaFrom(r))
	case "refresh_token":
		tokens, err = a.svc.Refresh(r.Context(), app, form.Get("refresh_token"), metaFrom(r))
	default:
		tokens, err = a.svc.ClientCredentials(r.Context(), app, metaFrom(r))
	}
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) && de.Kind != domain.KindInternal {
			// RFC 6749 section 5.2: one code for every unusable grant.
			return fail(http.StatusBadRequest, "invalid_grant", "the authorization code or refresh token is invalid, expired or already used")
		}
		return err
	}
	writeJSON(w, http.StatusOK, oauthTokenResponse{Tokens: tokens, Scope: scope})
	return nil
}
