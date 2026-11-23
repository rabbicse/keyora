package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
)

// This file implements the login protocol of the original auth tutorial so
// that clients written against it keep working. It is only reachable when the
// operator enables the tutorial-compatibility API.
//
// The protocol: the client derives verifier = Argon2id(password, salt) and
// registers salt and verifier. To log in it asks for a random challenge and
// answers with HMAC-SHA256(verifier, challenge).
//
// Its weakness is inherent and cannot be fixed without changing the protocol:
// the stored verifier is all an attacker needs to compute a valid proof, so a
// leaked credentials table is as good as a table of plaintext passwords. Use
// it only for migration. What Keyora does improve around it: nothing secret is
// logged, unknown users are indistinguishable from known ones, challenges and
// login tokens are single use, accounts lock after repeated failures, and
// every attempt is audited.

const (
	legacyChallengeTTL  = 2 * time.Minute
	legacyLoginTokenTTL = 2 * time.Minute
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

type legacyChallenge struct {
	tenantID string
	username string
	value    []byte
	expires  time.Time
}

type legacyLoginToken struct {
	tenantID string
	userID   string
	expires  time.Time
}

// legacyState holds challenges and login tokens in process memory, as the
// tutorial did. Both live two minutes, so they are lost on restart without
// harm; with several instances a login must reach the same one twice.
type legacyState struct {
	mu         sync.Mutex
	challenges map[string]legacyChallenge
	tokens     map[string]legacyLoginToken
	fakeSalt   []byte
}

func newLegacyState() *legacyState {
	return &legacyState{challenges: map[string]legacyChallenge{}, tokens: map[string]legacyLoginToken{}, fakeSalt: security.RandomBytes(32)}
}

func (l *legacyState) sweep(now time.Time) {
	for k, c := range l.challenges {
		if !now.Before(c.expires) {
			delete(l.challenges, k)
		}
	}
	for k, t := range l.tokens {
		if !now.Before(t.expires) {
			delete(l.tokens, k)
		}
	}
}

// LegacyRegister creates a user from a client-derived salt and verifier.
func (s *Service) LegacyRegister(ctx context.Context, app *domain.Application, username, rawEmail, saltB64, verifierB64 string, m Meta) (*domain.User, error) {
	if !usernameRe.MatchString(username) {
		return nil, domain.Invalid("username", "must be 3-64 letters, digits, '.', '_' or '-'")
	}
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return nil, domain.Invalid("salt", "must be 8-64 bytes, base64url without padding")
	}
	verifier, err := base64.RawURLEncoding.DecodeString(verifierB64)
	if err != nil || len(verifier) < 16 || len(verifier) > 128 {
		return nil, domain.Invalid("verifier", "must be 16-128 bytes, base64url without padding")
	}
	if _, err := s.store.GetLegacyCredential(ctx, app.TenantID, username); err == nil {
		return nil, domain.E(domain.KindConflict, "user_exists", "user already exists")
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	now := s.now()
	// No password hash: this account can only use the challenge login until
	// its owner sets a password through the normal reset flow.
	u := &domain.User{ID: security.NewID(), TenantID: app.TenantID, Email: email, Name: username,
		Status: domain.StatusActive, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "user_exists", "email already registered")
		}
		return nil, err
	}
	if err := s.store.CreateLegacyCredential(ctx, &domain.LegacyCredential{UserID: u.ID, TenantID: u.TenantID,
		Username: username, Salt: salt, Verifier: verifier, CreatedAt: now}); err != nil {
		_ = s.store.DeleteUser(ctx, u.TenantID, u.ID)
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "user_exists", "user already exists")
		}
		return nil, err
	}
	m.ActorType, m.ActorID = "user", u.ID
	s.audit(ctx, u.TenantID, "user.registered", m, u.ID, map[string]string{"client_id": app.ClientID, "flow": "legacy"})
	return u, nil
}

// LegacyChallenge starts a login. Unknown usernames get a believable salt and
// a challenge that can never be answered, so the response does not reveal
// whether an account exists (the tutorial answered 401 for unknown users).
func (s *Service) LegacyChallenge(ctx context.Context, app *domain.Application, username string) (id string, challenge, salt []byte, err error) {
	cred, err := s.store.GetLegacyCredential(ctx, app.TenantID, username)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return "", nil, nil, err
	}
	now := s.now()
	l := s.legacy
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	id, challenge = security.NewToken(""), security.RandomBytes(32)
	if cred == nil {
		mac := hmac.New(sha256.New, l.fakeSalt)
		mac.Write([]byte(app.TenantID + "\x00" + username))
		return id, challenge, mac.Sum(nil)[:16], nil
	}
	if len(l.challenges) < 100_000 { // bound memory under a flood; excess logins simply fail
		l.challenges[id] = legacyChallenge{tenantID: app.TenantID, username: username, value: challenge, expires: now.Add(legacyChallengeTTL)}
	}
	return id, challenge, cred.Salt, nil
}

// LegacyVerify checks the proof for a challenge and returns a short-lived,
// single-use login token for the legacy authorize endpoint.
func (s *Service) LegacyVerify(ctx context.Context, app *domain.Application, username, challengeID string, proof []byte, m Meta) (string, error) {
	now := s.now()
	l := s.legacy
	l.mu.Lock()
	ch, ok := l.challenges[challengeID]
	delete(l.challenges, challengeID) // one attempt per challenge
	l.mu.Unlock()
	if !ok || !now.Before(ch.expires) || ch.tenantID != app.TenantID || ch.username != username {
		return "", domain.ErrInvalidCredentials
	}
	cred, err := s.store.GetLegacyCredential(ctx, app.TenantID, username)
	if errors.Is(err, domain.ErrNotFound) {
		return "", domain.ErrInvalidCredentials
	}
	if err != nil {
		return "", err
	}
	u, err := s.store.GetUser(ctx, cred.TenantID, cred.UserID)
	if err != nil {
		return "", domain.ErrInvalidCredentials
	}
	m.ActorType, m.ActorID = "user", u.ID
	if u.LockedUntil != nil {
		if now.Before(*u.LockedUntil) {
			s.audit(ctx, u.TenantID, "user.login.failed", m, u.ID, map[string]string{"reason": "locked", "flow": "legacy"})
			return "", domain.ErrInvalidCredentials
		}
		if err := s.store.ClearLoginFailures(ctx, u.TenantID, u.ID, nil); err != nil {
			return "", err
		}
	}
	mac := hmac.New(sha256.New, cred.Verifier)
	mac.Write(ch.value)
	if !hmac.Equal(mac.Sum(nil), proof) {
		n, err := s.store.IncrementFailedLogins(ctx, u.TenantID, u.ID)
		if err != nil {
			return "", err
		}
		s.audit(ctx, u.TenantID, "user.login.failed", m, u.ID, map[string]string{"reason": "bad_proof", "flow": "legacy"})
		if n >= s.opt.MaxFailedLogins {
			if err := s.store.LockUser(ctx, u.TenantID, u.ID, now.Add(s.opt.LockoutDuration)); err != nil {
				return "", err
			}
			s.audit(ctx, u.TenantID, "user.locked", m, u.ID, map[string]string{"failed_attempts": itoa(n)})
		}
		return "", domain.ErrInvalidCredentials
	}
	if u.Status != domain.StatusActive {
		return "", domain.ErrInvalidCredentials
	}
	if err := s.store.ClearLoginFailures(ctx, u.TenantID, u.ID, &now); err != nil {
		return "", err
	}
	token := security.NewToken("")
	l.mu.Lock()
	l.tokens[security.HashToken(token)] = legacyLoginToken{tenantID: u.TenantID, userID: u.ID, expires: now.Add(legacyLoginTokenTTL)}
	l.mu.Unlock()
	return token, nil
}

// LegacyAuthorize exchanges a login token for an authorization code, as the
// tutorial's GET /authorize did. The code carries no PKCE challenge and can
// only be redeemed at the legacy token endpoint by a confidential application
// presenting its secret.
func (s *Service) LegacyAuthorize(ctx context.Context, loginToken string, req AuthorizeRequest, m Meta) (string, error) {
	app, err := s.AuthorizeClient(ctx, req)
	if err != nil {
		return "", err
	}
	if app.Type != domain.AppConfidential {
		// Without PKCE the client secret is the only thing binding the code.
		return "", domain.ErrInvalidClient
	}
	if req.ResponseType != "code" {
		return "", domain.Invalid("response_type", "unsupported response type")
	}
	now := s.now()
	l := s.legacy
	l.mu.Lock()
	lt, ok := l.tokens[security.HashToken(loginToken)]
	delete(l.tokens, security.HashToken(loginToken)) // single use
	l.mu.Unlock()
	if !ok || !now.Before(lt.expires) || lt.tenantID != app.TenantID {
		return "", domain.E(domain.KindUnauthenticated, "invalid_login_token", "invalid login token")
	}
	u, err := s.store.GetUser(ctx, lt.tenantID, lt.userID)
	if err != nil || u.Status != domain.StatusActive {
		return "", domain.E(domain.KindUnauthenticated, "invalid_login_token", "invalid login token")
	}
	m.ActorType, m.ActorID = "user", u.ID
	sess, err := s.openSession(ctx, app, u, m)
	if err != nil {
		return "", err
	}
	code := security.NewToken("kyc_")
	if err := s.store.CreateAuthorizationCode(ctx, &domain.AuthorizationCode{
		ID: security.NewID(), CodeHash: security.HashToken(code), TenantID: u.TenantID, ApplicationID: app.ID,
		UserID: u.ID, SessionID: sess.ID, RedirectURI: req.RedirectURI, Scope: req.Scope,
		CreatedAt: now, ExpiresAt: now.Add(AuthorizationCodeTTL),
	}); err != nil {
		return "", err
	}
	s.audit(ctx, u.TenantID, "user.login.succeeded", m, u.ID,
		map[string]string{"session_id": sess.ID, "client_id": app.ClientID, "flow": "legacy"})
	return code, nil
}

// LegacyExchangeCode redeems a code issued by LegacyAuthorize.
func (s *Service) LegacyExchangeCode(ctx context.Context, app *domain.Application, code, redirectURI string, m Meta) (*Tokens, string, error) {
	return s.exchangeCode(ctx, app, code, redirectURI, "", true, m)
}
