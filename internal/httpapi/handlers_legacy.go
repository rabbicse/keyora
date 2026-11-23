package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
)

// This file serves the HTTP API of the original auth tutorial
// (go-projects/projects/auth-tutorial, part-jwt) so existing clients keep
// working. It is registered only when KEYORA_LEGACY_TUTORIAL_API=true. Paths,
// request bodies and response shapes match the tutorial, including its flat
// {"error": "..."} failures. See docs/legacy-tutorial-api.md.

var legacyPaths = map[string]bool{
	"/users/register": true, "/login/challenge": true, "/login/verify": true,
	"/authorize": true, "/token": true, "/oauth/introspect": true,
}

// legacyPath reports whether a path belongs to the compatibility API, so the
// credential rate limit covers it too.
func (a *API) legacyPath(path string) bool { return a.cfg.LegacyClientID != "" && legacyPaths[path] }

func (a *API) legacyRoutes() {
	a.handle("GET /health", a.legacyHealth)
	a.handle("POST /users/register", a.legacyRegister)
	a.handle("POST /login/challenge", a.legacyChallenge)
	a.handle("POST /login/verify", a.legacyVerify)
	a.handle("GET /authorize", a.legacyAuthorize)
	a.handle("POST /token", a.legacyToken)
	a.handle("POST /oauth/introspect", a.legacyIntrospect)
}

func legacyError(w http.ResponseWriter, status int, msg string) error {
	writeJSON(w, status, map[string]string{"error": msg})
	return nil
}

// legacyFail maps a service error to the tutorial's error shape.
func (a *API) legacyFail(w http.ResponseWriter, r *http.Request, err error, fallback int) error {
	var de *domain.Error
	if !errors.As(err, &de) {
		a.log.Error("legacy API error", "request_id", requestID(r), "error", err)
		return legacyError(w, http.StatusInternalServerError, "internal error")
	}
	status := statusFor(de.Kind)
	if fallback != 0 && de.Kind == domain.KindInvalid {
		status = fallback
	}
	msg := de.Message
	for _, v := range de.Details {
		msg += ": " + v
		break
	}
	return legacyError(w, status, msg)
}

// legacyApp is the application whose tenant legacy users live in.
func (a *API) legacyApp(r *http.Request) (*domain.Application, error) {
	return a.svc.AuthorizeClientID(r.Context(), a.cfg.LegacyClientID)
}

func legacyJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst) == nil
}

func (a *API) legacyHealth(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (a *API) legacyRegister(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
	}
	if !legacyJSON(w, r, &req) {
		return legacyError(w, http.StatusBadRequest, "invalid request")
	}
	app, err := a.legacyApp(r)
	if err != nil {
		return a.legacyFail(w, r, err, 0)
	}
	u, err := a.svc.LegacyRegister(r.Context(), app, req.Username, req.Email, req.Salt, req.Verifier, metaFrom(r))
	if err != nil {
		return a.legacyFail(w, r, err, http.StatusBadRequest)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "username": req.Username})
	return nil
}

func (a *API) legacyChallenge(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Username string `json:"username"`
	}
	if !legacyJSON(w, r, &req) {
		return legacyError(w, http.StatusBadRequest, "bad request")
	}
	app, err := a.legacyApp(r)
	if err != nil {
		return a.legacyFail(w, r, err, 0)
	}
	id, challenge, salt, err := a.svc.LegacyChallenge(r.Context(), app, req.Username)
	if err != nil {
		return a.legacyFail(w, r, err, 0)
	}
	enc := base64.RawURLEncoding
	writeJSON(w, http.StatusOK, map[string]string{"challenge_id": id, "challenge": enc.EncodeToString(challenge), "salt": enc.EncodeToString(salt)})
	return nil
}

func (a *API) legacyVerify(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Username    string `json:"username"`
		ChallengeID string `json:"challenge_id"`
		Proof       string `json:"proof"`
	}
	if !legacyJSON(w, r, &req) {
		return legacyError(w, http.StatusBadRequest, "bad request")
	}
	proof, err := base64.RawURLEncoding.DecodeString(req.Proof)
	if err != nil {
		return legacyError(w, http.StatusBadRequest, "invalid proof encoding")
	}
	app, err := a.legacyApp(r)
	if err != nil {
		return a.legacyFail(w, r, err, 0)
	}
	token, err := a.svc.LegacyVerify(r.Context(), app, req.Username, req.ChallengeID, proof, metaFrom(r))
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return legacyError(w, http.StatusUnauthorized, "invalid login")
		}
		return a.legacyFail(w, r, err, 0)
	}
	writeJSON(w, http.StatusOK, map[string]string{"login_token": token})
	return nil
}

func (a *API) legacyAuthorize(w http.ResponseWriter, r *http.Request) error {
	token := bearer(r)
	if token == "" {
		return legacyError(w, http.StatusUnauthorized, "missing login token")
	}
	q := r.URL.Query()
	req := service.AuthorizeRequest{ResponseType: q.Get("response_type"), ClientID: q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"), Scope: q.Get("scope"), State: q.Get("state")}
	code, err := a.svc.LegacyAuthorize(r.Context(), token, req, metaFrom(r))
	if err != nil {
		return a.legacyFail(w, r, err, http.StatusBadRequest)
	}
	// Built with net/url: the tutorial concatenated the state unescaped.
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return legacyError(w, http.StatusBadRequest, "invalid redirect uri")
	}
	v := u.Query()
	v.Set("code", code)
	v.Set("state", req.State)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

func (a *API) legacyToken(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return legacyError(w, http.StatusBadRequest, "bad request")
	}
	f := r.PostForm
	var (
		tokens *service.Tokens
		scope  string
		err    error
	)
	switch f.Get("grant_type") {
	case "authorization_code":
		var app *domain.Application
		if app, err = a.client(r, f.Get("client_id"), f.Get("client_secret"), true); err == nil {
			tokens, scope, err = a.svc.LegacyExchangeCode(r.Context(), app, f.Get("code"), f.Get("redirect_uri"), metaFrom(r))
		}
	case "refresh_token":
		// The tutorial accepted a bare refresh token. A token here is bound to
		// its application, so the client is identified when given, and falls
		// back to the configured legacy application otherwise.
		var app *domain.Application
		if f.Get("client_id") != "" {
			app, err = a.client(r, f.Get("client_id"), f.Get("client_secret"), true)
		} else {
			app, err = a.legacyApp(r)
		}
		if err == nil {
			tokens, err = a.svc.Refresh(r.Context(), app, f.Get("refresh_token"), metaFrom(r))
		}
	default:
		return legacyError(w, http.StatusBadRequest, "unsupported grant type")
	}
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) && de.Kind != domain.KindInternal {
			return legacyError(w, http.StatusBadRequest, strings.ReplaceAll(de.Code, "_", " "))
		}
		return a.legacyFail(w, r, err, 0)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tokens.AccessToken, "refresh_token": tokens.RefreshToken, "token_type": "Bearer",
		"expires_in": tokens.ExpiresIn, "scope": scope, "id_token": tokens.IDToken,
	})
	return nil
}

func (a *API) legacyIntrospect(w http.ResponseWriter, r *http.Request) error {
	// The tutorial guarded this with the hard-coded pair resource-server /
	// secret. That is not carried over: use a confidential application.
	id, secret, ok := r.BasicAuth()
	if !ok {
		return legacyError(w, http.StatusUnauthorized, "invalid client")
	}
	app, err := a.svc.AuthenticateClient(r.Context(), id, secret, "", true)
	if err != nil {
		return legacyError(w, http.StatusUnauthorized, "invalid client")
	}
	var req struct {
		Token string `json:"token"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		legacyJSON(w, r, &req)
	} else if r.ParseForm() == nil {
		req.Token = r.PostForm.Get("token")
	}
	res, err := a.svc.Introspect(r.Context(), app, req.Token)
	if err != nil {
		return a.legacyFail(w, r, err, 0)
	}
	if !res.Active {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": true, "sub": res.Subject, "client_id": res.ClientID, "exp": res.ExpiresAt})
	return nil
}
