package httpapi

import (
	"errors"
	"net/http"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
)

// This file implements the OAuth 2.0 endpoints:
//
//   - the authorization endpoint (authorization code flow, RFC 6749 section
//     4.1, with mandatory PKCE, RFC 7636);
//   - the token endpoint (authorization_code, refresh_token and
//     client_credentials grants);
//   - authorization server metadata (RFC 8414).
//
// Keyora is API only. It serves no page and never redirects a browser: the
// application collects the user's credentials in its own interface and
// obtains the authorization code with one JSON call
// (POST /api/v1/oauth/authorize).
//
// The token and metadata endpoints speak the RFCs' wire formats rather than
// the Keyora envelope so that standard OAuth client libraries can redeem
// codes and refresh tokens unchanged.

// authorize issues an authorization code to the application's own sign-in
// screen: the authorization request and the user's credentials go in as JSON,
// the code comes back as JSON. No cookie is read or set, so there is no
// ambient credential for another site to abuse.
func (a *API) authorize(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		ResponseType        string `json:"response_type"`
		State               string `json:"state"`
		Scope               string `json:"scope"`
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Email               string `json:"email"`
		Password            string `json:"password"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	res, err := a.svc.AuthorizeWithPassword(r.Context(), service.AuthorizeRequest{
		ClientID: req.ClientID, RedirectURI: req.RedirectURI, ResponseType: req.ResponseType,
		State: req.State, Scope: req.Scope, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
	}, req.Email, req.Password, r.Header.Get("Origin"), metaFrom(r))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, res)
	return nil
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
		if errors.Is(service.GrantError(err), domain.ErrInvalidGrant) {
			// RFC 6749 section 5.2: one code for every unusable grant.
			return fail(http.StatusBadRequest, "invalid_grant", "the authorization code or refresh token is invalid, expired or already used")
		}
		return err
	}
	writeJSON(w, http.StatusOK, oauthTokenResponse{Tokens: tokens, Scope: scope})
	return nil
}
