package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
)

// AuthorizationCodeTTL is how long a code may sit between the redirect and
// the token request. RFC 6749 recommends at most ten minutes; one is plenty
// for a redirect and limits the window in which a leaked code is useful.
const AuthorizationCodeTTL = 60 * time.Second

var (
	// A PKCE S256 challenge is the base64url of a SHA-256 digest: 43 characters.
	challengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// RFC 7636 section 4.1: 43-128 characters from the unreserved set.
	verifierRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// AuthorizeRequest is a parsed authorization request (RFC 6749 section 4.1.1
// with the PKCE parameters of RFC 7636).
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce is the OpenID Connect nonce, echoed in the ID token.
	Nonce string
}

// AuthorizeClient resolves the application and checks the redirect URI by
// exact string comparison. If this fails the user must NOT be redirected: the
// redirect target itself is what could not be trusted.
func (s *Service) AuthorizeClient(ctx context.Context, req AuthorizeRequest) (*domain.Application, error) {
	app, err := s.store.GetApplicationByClientID(ctx, req.ClientID)
	if errors.Is(err, domain.ErrNotFound) || req.ClientID == "" {
		return nil, domain.ErrInvalidClient
	}
	if err != nil {
		return nil, err
	}
	if app.Status != domain.StatusActive {
		return nil, domain.ErrInvalidClient
	}
	if ok, err := s.tenantActive(ctx, app.TenantID); err != nil {
		return nil, err
	} else if !ok {
		return nil, domain.ErrInvalidClient
	}
	if req.RedirectURI == "" || !containsString(app.RedirectURIs, req.RedirectURI) {
		return nil, domain.ErrInvalidRedirectURI
	}
	return app, nil
}

// AuthorizeClientID resolves an active application of an active tenant by
// client ID without checking any redirect URI.
func (s *Service) AuthorizeClientID(ctx context.Context, clientID string) (*domain.Application, error) {
	app, err := s.store.GetApplicationByClientID(ctx, clientID)
	if errors.Is(err, domain.ErrNotFound) || clientID == "" {
		return nil, domain.ErrInvalidClient
	}
	if err != nil {
		return nil, err
	}
	if app.Status != domain.StatusActive {
		return nil, domain.ErrInvalidClient
	}
	if ok, err := s.tenantActive(ctx, app.TenantID); err != nil {
		return nil, err
	} else if !ok {
		return nil, domain.ErrInvalidClient
	}
	return app, nil
}

// ValidateAuthorizeRequest checks the parts of a request whose failure is
// reported back to the application through the redirect. PKCE with S256 is
// mandatory for every client, confidential ones included, and the "plain"
// method is refused: it offers no protection if the challenge is observed.
func ValidateAuthorizeRequest(req AuthorizeRequest) (oauthError, description string) {
	switch {
	case req.ResponseType != "code":
		return "unsupported_response_type", "only response_type=code is supported"
	case req.CodeChallenge == "":
		return "invalid_request", "code_challenge is required (PKCE)"
	case req.CodeChallengeMethod != "S256":
		return "invalid_request", "code_challenge_method must be S256"
	case !challengeRe.MatchString(req.CodeChallenge):
		return "invalid_request", "code_challenge must be a base64url-encoded SHA-256 digest"
	case len(req.State) > 512 || len(req.Scope) > 512 || len(req.Nonce) > 512:
		return "invalid_request", "state, scope and nonce must be at most 512 characters"
	}
	return "", ""
}

// Authorization is the outcome of a successful authorization request: the
// single-use code and the redirect URI it is bound to.
type Authorization struct {
	Code string `json:"code"`
	// State is the request's state, echoed so the caller can match the answer.
	State string `json:"state,omitempty"`
	// RedirectURI is the registered redirect URI the code is bound to.
	RedirectURI string `json:"redirect_uri"`
	// RedirectTo is RedirectURI with code, state and iss (RFC 9207) appended:
	// the complete authorization response of RFC 6749 section 4.1.2.
	RedirectTo string `json:"redirect_to"`
	// ExpiresIn is the code's lifetime in seconds.
	ExpiresIn int64  `json:"expires_in"`
	Issuer    string `json:"iss"`
}

// RedirectURL appends params, the request's state and the issuer (RFC 9207,
// which lets a client of several authorization servers detect a mix-up) to
// the request's redirect URI. Only call it once AuthorizeClient has accepted
// that URI.
func (s *Service) RedirectURL(req AuthorizeRequest, params url.Values) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", domain.ErrInvalidRedirectURI
	}
	q := u.Query()
	for k := range params {
		q.Set(k, params.Get(k))
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", s.opt.Issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// AuthorizeWithPassword is the whole authorization request as one call, for
// applications that collect the user's credentials themselves (Keyora serves
// no pages): it checks the application
// and redirect URI, the request (PKCE is mandatory) and the user's
// credentials, and returns the authorization code.
//
// origin is the browser's Origin header, empty for other callers. A browser
// may only call from an origin registered on the application, so a page on
// another site cannot use a visitor's browser to try passwords.
//
// Every failure is a domain.Error; nothing is redirected. An invalid request
// carries the OAuth error code (invalid_request, unsupported_response_type)
// as its Code.
func (s *Service) AuthorizeWithPassword(ctx context.Context, req AuthorizeRequest, email, password, origin string, m Meta) (*Authorization, error) {
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	app, err := s.AuthorizeClient(ctx, req)
	if errors.Is(err, domain.ErrInvalidClient) {
		// Not a failed authentication (nothing secret was presented): the
		// client_id simply does not name a usable application.
		return nil, domain.E(domain.KindInvalid, "invalid_client", "client_id does not name an active application")
	}
	if err != nil {
		return nil, err
	}
	if origin != "" && !containsString(app.AllowedOrigins, origin) {
		return nil, domain.ErrOriginNotAllowed
	}
	if code, desc := ValidateAuthorizeRequest(req); code != "" {
		return nil, domain.E(domain.KindInvalid, code, desc)
	}
	code, err := s.Authorize(ctx, app, req, email, password, m)
	if err != nil {
		return nil, err
	}
	target, err := s.RedirectURL(req, url.Values{"code": {code}})
	if err != nil {
		return nil, err
	}
	return &Authorization{Code: code, State: req.State, RedirectURI: req.RedirectURI, RedirectTo: target,
		ExpiresIn: int64(AuthorizationCodeTTL.Seconds()), Issuer: s.opt.Issuer}, nil
}

// Authorize checks the user's credentials and returns a single-use
// authorization code bound to the application, redirect URI and PKCE
// challenge. The caller has already validated app and req.
func (s *Service) Authorize(ctx context.Context, app *domain.Application, req AuthorizeRequest, email, password string, m Meta) (string, error) {
	u, m, err := s.verifyCredentials(ctx, app, email, password, m)
	if err != nil {
		return "", err
	}
	sess, err := s.openSession(ctx, app, u, m)
	if err != nil {
		return "", err
	}
	now := s.now()
	code := security.NewToken("kyc_")
	if err := s.store.CreateAuthorizationCode(ctx, &domain.AuthorizationCode{
		ID: security.NewID(), CodeHash: security.HashToken(code), TenantID: u.TenantID, ApplicationID: app.ID,
		UserID: u.ID, SessionID: sess.ID, RedirectURI: req.RedirectURI, CodeChallenge: req.CodeChallenge,
		Scope: req.Scope, Nonce: req.Nonce, CreatedAt: now, ExpiresAt: now.Add(AuthorizationCodeTTL),
	}); err != nil {
		return "", err
	}
	s.audit(ctx, u.TenantID, "user.login.succeeded", m, u.ID,
		map[string]string{"session_id": sess.ID, "client_id": app.ClientID, "flow": "authorization_code"})
	return code, nil
}

// ExchangeCode redeems an authorization code for tokens (RFC 6749 section
// 4.1.3) after checking the PKCE verifier (RFC 7636 section 4.6).
//
// Every failure answers invalid_grant without saying which check failed. A
// code presented twice revokes the session it opened, as the RFC advises,
// because a replay means the code leaked.
func (s *Service) ExchangeCode(ctx context.Context, app *domain.Application, code, redirectURI, verifier string, m Meta) (*Tokens, string, error) {
	return s.exchangeCode(ctx, app, code, redirectURI, verifier, false, m)
}

// exchangeCode does the work of ExchangeCode. legacy selects which kind of
// code is acceptable: the standard endpoint only redeems codes that carry a
// PKCE challenge, and the tutorial-compatibility endpoint only redeems codes
// issued without one. Neither can redeem the other's.
func (s *Service) exchangeCode(ctx context.Context, app *domain.Application, code, redirectURI, verifier string, legacy bool, m Meta) (*Tokens, string, error) {
	if code == "" {
		return nil, "", domain.ErrInvalidGrant
	}
	now := s.now()
	ac, reused, err := s.store.ConsumeAuthorizationCode(ctx, security.HashToken(code), now)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, "", domain.ErrInvalidGrant
	}
	if err != nil {
		return nil, "", err
	}
	m.ActorType, m.ActorID = "user", ac.UserID
	if ac.ApplicationID != app.ID {
		return nil, "", domain.ErrInvalidGrant
	}
	if reused {
		if err := s.store.RevokeSession(ctx, ac.SessionID, now); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, "", err
		}
		s.audit(ctx, ac.TenantID, "code.reuse_detected", m, ac.UserID, map[string]string{"session_id": ac.SessionID})
		return nil, "", domain.ErrInvalidGrant
	}
	proofOK := (ac.CodeChallenge == "") == legacy
	if proofOK && !legacy {
		proofOK = verifyPKCE(verifier, ac.CodeChallenge)
	}
	if !now.Before(ac.ExpiresAt) || ac.RedirectURI != redirectURI || !proofOK {
		// The code is spent either way; a wrong verifier does not get a second try.
		_ = s.store.RevokeSession(ctx, ac.SessionID, now)
		return nil, "", domain.ErrInvalidGrant
	}
	sess, err := s.store.GetSession(ctx, ac.SessionID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && !sess.Active(now)) {
		return nil, "", domain.ErrInvalidGrant
	}
	if err != nil {
		return nil, "", err
	}
	u, err := s.store.GetUser(ctx, ac.TenantID, ac.UserID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && u.Status != domain.StatusActive) {
		return nil, "", domain.ErrInvalidGrant
	}
	if err != nil {
		return nil, "", err
	}
	tokens, err := s.issueTokens(ctx, app, u, sess)
	if err != nil {
		return nil, "", err
	}
	if hasScope(ac.Scope, "openid") {
		if tokens.IDToken, err = s.issueIDToken(app, u, sess, ac); err != nil {
			return nil, "", err
		}
	}
	s.audit(ctx, ac.TenantID, "token.code_exchanged", m, ac.UserID, map[string]string{"session_id": sess.ID})
	return tokens, ac.Scope, nil
}

// GrantError is how every transport reports a failed token request
// (authorization_code or refresh_token grant): RFC 6749 section 5.2 has one
// code, invalid_grant, for every unusable grant, and Keyora gives no hint
// about which check failed (unknown, expired, replayed, wrong verifier or
// redirect URI, reused refresh token). Internal errors pass through
// unchanged so they are logged and masked as usual.
func GrantError(err error) error {
	var de *domain.Error
	if errors.As(err, &de) && de.Kind != domain.KindInternal {
		return domain.ErrInvalidGrant
	}
	return err
}

// verifyPKCE checks BASE64URL(SHA256(verifier)) == challenge in constant time.
func verifyPKCE(verifier, challenge string) bool {
	if !verifierRe.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return security.ConstantTimeEqual(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}
