package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/mailer"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/jwt"
)

// Tokens is what a successful sign-in or refresh returns.
type Tokens struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int64  `json:"refresh_expires_in,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	// IDToken is set by the authorization code flow when the openid scope was requested.
	IDToken string `json:"id_token,omitempty"`
}

// Principal is an authenticated caller of Keyora's own API.
type Principal struct {
	Root        bool
	UserID      string
	TenantID    string
	SessionID   string
	ClientID    string
	Roles       []string
	Permissions []string
}

// CanManage reports whether the principal may administer the tenant.
func (p *Principal) CanManage(tenantID string) bool {
	if p.Root {
		return true
	}
	if p.TenantID != tenantID {
		return false
	}
	for _, perm := range p.Permissions {
		if perm == domain.PermissionAdmin {
			return true
		}
	}
	return false
}

// Introspection is the live state of a token as seen by Keyora.
type Introspection struct {
	Active      bool     `json:"active"`
	Subject     string   `json:"sub,omitempty"`
	TenantID    string   `json:"tid,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   string   `json:"sid,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Issuer      string   `json:"iss,omitempty"`
	ExpiresAt   int64    `json:"exp,omitempty"`
	IssuedAt    int64    `json:"iat,omitempty"`
}

// AuthenticateClient identifies the calling application. Confidential
// applications must present their secret; public ones are identified by
// client_id alone and, when called from a browser, by an allowed Origin.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, secret, origin string, requireConfidential bool) (*domain.Application, error) {
	if clientID == "" {
		return nil, domain.ErrInvalidClient
	}
	app, err := s.store.GetApplicationByClientID(ctx, clientID)
	if errors.Is(err, domain.ErrNotFound) {
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
	if app.Type == domain.AppConfidential {
		if secret == "" || !security.ConstantTimeEqual(security.HashToken(secret), app.ClientSecretHash) {
			return nil, domain.ErrInvalidClient
		}
		return app, nil
	}
	if requireConfidential {
		return nil, domain.E(domain.KindUnauthenticated, "invalid_client", "this operation requires a confidential application")
	}
	if origin != "" && !containsString(app.AllowedOrigins, origin) {
		return nil, domain.ErrOriginNotAllowed
	}
	return app, nil
}

func (s *Service) tenantActive(ctx context.Context, tenantID string) (bool, error) {
	t, err := s.store.GetTenant(ctx, tenantID)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return t.Status == domain.StatusActive, nil
}

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

// Register creates a user in the application's tenant.
func (s *Service) Register(ctx context.Context, app *domain.Application, in RegisterInput, m Meta) (*domain.User, error) {
	u, err := s.createUser(ctx, app.TenantID, in.Email, in.Password, in.Name, false)
	if err != nil {
		return nil, err
	}
	m.ActorType, m.ActorID = "user", u.ID
	s.audit(ctx, u.TenantID, "user.registered", m, u.ID, map[string]string{"client_id": app.ClientID})
	s.sendVerification(ctx, u)
	return u, nil
}

func (s *Service) createUser(ctx context.Context, tenantID, rawEmail, password, rawName string, verified bool) (*domain.User, error) {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return nil, err
	}
	if err := s.validatePassword(password, email); err != nil {
		return nil, err
	}
	name, err := validateDisplayName("name", rawName, false)
	if err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	now := s.now()
	u := &domain.User{ID: security.NewID(), TenantID: tenantID, Email: email, Name: name, PasswordHash: hash,
		Status: domain.StatusActive, EmailVerified: verified, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.ErrEmailTaken
		}
		return nil, err
	}
	return u, nil
}

// Login verifies credentials and opens a session.
func (s *Service) Login(ctx context.Context, app *domain.Application, rawEmail, password string, m Meta) (*Tokens, *domain.User, error) {
	u, m, err := s.verifyCredentials(ctx, app, rawEmail, password, m)
	if err != nil {
		return nil, nil, err
	}
	sess, err := s.openSession(ctx, app, u, m)
	if err != nil {
		return nil, nil, err
	}
	tokens, err := s.issueTokens(ctx, app, u, sess)
	if err != nil {
		return nil, nil, err
	}
	s.audit(ctx, u.TenantID, "user.login.succeeded", m, u.ID, map[string]string{"session_id": sess.ID, "client_id": app.ClientID})
	return tokens, u, nil
}

// verifyCredentials is the single place a password is checked: lockout,
// timing equalisation, status and verification rules all live here, so every
// sign-in path (direct login and the hosted authorization page) shares them.
func (s *Service) verifyCredentials(ctx context.Context, app *domain.Application, rawEmail, password string, m Meta) (*domain.User, Meta, error) {
	now := s.now()
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		email = ""
	}
	var u *domain.User
	if email != "" {
		u, err = s.store.GetUserByEmail(ctx, app.TenantID, email)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, m, err
		}
	}
	if u == nil {
		s.hasher.Verify(password, s.dummyHash)
		s.audit(ctx, app.TenantID, "user.login.failed", m, "", map[string]string{"reason": "unknown_user", "client_id": app.ClientID})
		return nil, m, domain.ErrInvalidCredentials
	}
	m.ActorType, m.ActorID = "user", u.ID

	if u.LockedUntil != nil {
		if now.Before(*u.LockedUntil) {
			s.audit(ctx, u.TenantID, "user.login.failed", m, u.ID, map[string]string{"reason": "locked", "client_id": app.ClientID})
			locked := *domain.ErrAccountLocked
			locked.Details = map[string]string{"retry_after_seconds": itoa(int(u.LockedUntil.Sub(now).Seconds()) + 1)}
			return nil, m, &locked
		}
		// The lock has run out: start counting from zero again.
		if err := s.store.ClearLoginFailures(ctx, u.TenantID, u.ID, nil); err != nil {
			return nil, m, err
		}
	}

	ok, rehash := s.hasher.Verify(password, u.PasswordHash)
	if !ok {
		n, err := s.store.IncrementFailedLogins(ctx, u.TenantID, u.ID)
		if err != nil {
			return nil, m, err
		}
		s.audit(ctx, u.TenantID, "user.login.failed", m, u.ID, map[string]string{"reason": "bad_password", "client_id": app.ClientID})
		if n >= s.opt.MaxFailedLogins {
			if err := s.store.LockUser(ctx, u.TenantID, u.ID, now.Add(s.opt.LockoutDuration)); err != nil {
				return nil, m, err
			}
			s.audit(ctx, u.TenantID, "user.locked", m, u.ID, map[string]string{"failed_attempts": itoa(n)})
		}
		return nil, m, domain.ErrInvalidCredentials
	}
	// Status is only revealed to callers who proved knowledge of the password.
	if u.Status != domain.StatusActive {
		return nil, m, domain.ErrAccountDisabled
	}
	if s.opt.RequireEmailVerification && !u.EmailVerified {
		return nil, m, domain.ErrEmailNotVerified
	}
	if rehash {
		if h, err := s.hasher.Hash(password); err == nil {
			u.PasswordHash, u.UpdatedAt = h, now
			if err := s.store.UpdateUser(ctx, u); err != nil {
				s.log.Warn("password rehash not stored", "user_id", u.ID, "error", err)
			}
		}
	}
	if err := s.store.ClearLoginFailures(ctx, u.TenantID, u.ID, &now); err != nil {
		return nil, m, err
	}
	u.LastLoginAt, u.LockedUntil = &now, nil

	return u, m, nil
}

func (s *Service) openSession(ctx context.Context, app *domain.Application, u *domain.User, m Meta) (*domain.Session, error) {
	now := s.now()
	sess := &domain.Session{ID: security.NewID(), TenantID: u.TenantID, UserID: u.ID, ApplicationID: app.ID,
		IP: m.IP, UserAgent: truncate(m.UserAgent, 256), CreatedAt: now, LastUsedAt: now,
		ExpiresAt: now.Add(time.Duration(app.RefreshTokenTTL) * time.Second)}
	return sess, s.store.CreateSession(ctx, sess)
}

// issueTokens mints an access token plus a fresh refresh token for the session.
func (s *Service) issueTokens(ctx context.Context, app *domain.Application, u *domain.User, sess *domain.Session) (*Tokens, error) {
	now := s.now()
	roles, perms, err := s.rolesOf(ctx, u.TenantID, u.ID)
	if err != nil {
		return nil, err
	}
	access, err := s.keys.Signer().Sign(jwt.Claims{
		Issuer: s.opt.Issuer, Subject: u.ID, Audience: jwt.Audience{app.ClientID},
		ExpiresAt: now.Add(time.Duration(app.AccessTokenTTL) * time.Second).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
		ID: security.NewID(), SessionID: sess.ID, TenantID: u.TenantID, ClientID: app.ClientID,
		Email: u.Email, Roles: roles, Permissions: perms, TokenUse: jwt.UseAccess,
	})
	if err != nil {
		return nil, err
	}
	refresh := security.NewToken("kyr_")
	if err := s.store.CreateRefreshToken(ctx, &domain.RefreshToken{ID: security.NewID(), SessionID: sess.ID,
		TokenHash: security.HashToken(refresh), CreatedAt: now, ExpiresAt: sess.ExpiresAt}); err != nil {
		return nil, err
	}
	return &Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: app.AccessTokenTTL,
		RefreshToken: refresh, RefreshExpiresIn: int64(sess.ExpiresAt.Sub(now).Seconds()), SessionID: sess.ID}, nil
}

func (s *Service) rolesOf(ctx context.Context, tenantID, userID string) (roles, perms []string, err error) {
	list, err := s.store.ListUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, nil, err
	}
	set := map[string]bool{}
	for _, r := range list {
		roles = append(roles, r.Name)
		for _, p := range r.Permissions {
			set[p] = true
		}
	}
	for p := range set {
		perms = append(perms, p)
	}
	sort.Strings(roles)
	sort.Strings(perms)
	return roles, perms, nil
}

// Refresh rotates a refresh token. Each token works once; presenting one a
// second time means it leaked, so the whole session is revoked.
func (s *Service) Refresh(ctx context.Context, app *domain.Application, refreshToken string, m Meta) (*Tokens, error) {
	if refreshToken == "" {
		return nil, domain.ErrInvalidRefreshToken
	}
	now := s.now()
	t, reused, err := s.store.ConsumeRefreshToken(ctx, security.HashToken(refreshToken), now)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	sess, err := s.store.GetSession(ctx, t.SessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	if sess.ApplicationID != app.ID {
		return nil, domain.ErrInvalidRefreshToken
	}
	m.ActorType, m.ActorID = "user", sess.UserID
	if reused {
		if err := s.store.RevokeSession(ctx, sess.ID, now); err != nil {
			return nil, err
		}
		s.audit(ctx, sess.TenantID, "token.reuse_detected", m, sess.UserID, map[string]string{"session_id": sess.ID})
		return nil, domain.ErrRefreshTokenReused
	}
	if !now.Before(t.ExpiresAt) || !sess.Active(now) {
		return nil, domain.ErrInvalidRefreshToken
	}
	u, err := s.store.GetUser(ctx, sess.TenantID, sess.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	if u.Status != domain.StatusActive {
		_ = s.store.RevokeSession(ctx, sess.ID, now)
		return nil, domain.ErrAccountDisabled
	}
	sess.LastUsedAt, sess.ExpiresAt = now, now.Add(time.Duration(app.RefreshTokenTTL)*time.Second)
	if err := s.store.TouchSession(ctx, sess.ID, sess.LastUsedAt, sess.ExpiresAt); err != nil {
		return nil, err
	}
	tokens, err := s.issueTokens(ctx, app, u, sess)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, sess.TenantID, "token.refreshed", m, sess.UserID, map[string]string{"session_id": sess.ID})
	return tokens, nil
}

// Logout revokes the session a refresh token belongs to. It always succeeds,
// so it cannot be used to probe which tokens exist.
func (s *Service) Logout(ctx context.Context, app *domain.Application, refreshToken string, m Meta) error {
	t, err := s.store.GetRefreshTokenByHash(ctx, security.HashToken(refreshToken))
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	sess, err := s.store.GetSession(ctx, t.SessionID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && sess.ApplicationID != app.ID) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.revokeSession(ctx, sess, m, "user.logout")
}

// LogoutSession revokes the session behind the caller's access token.
func (s *Service) LogoutSession(ctx context.Context, p *Principal, m Meta) error {
	sess, err := s.store.GetSession(ctx, p.SessionID)
	if err != nil {
		return err
	}
	return s.revokeSession(ctx, sess, m, "user.logout")
}

func (s *Service) revokeSession(ctx context.Context, sess *domain.Session, m Meta, event string) error {
	if sess.RevokedAt != nil {
		return nil
	}
	if err := s.store.RevokeSession(ctx, sess.ID, s.now()); err != nil {
		return err
	}
	if m.ActorType == "" {
		m.ActorType, m.ActorID = "user", sess.UserID
	}
	s.audit(ctx, sess.TenantID, event, m, sess.UserID, map[string]string{"session_id": sess.ID})
	return nil
}

func (s *Service) verifyJWT(token string) (*jwt.Claims, error) {
	c, err := jwt.Verify(token, s.keys.PublicKey, jwt.Validation{Issuer: s.opt.Issuer, Now: s.opt.Clock})
	if err != nil {
		return nil, err
	}
	if c.IsIDToken() {
		return nil, errors.New("an ID token is not an access token")
	}
	return c, nil
}

// liveUser checks everything a signature cannot: that the session, user and
// tenant behind the claims are all still in good standing.
func (s *Service) liveUser(ctx context.Context, c *jwt.Claims) (*domain.User, bool, error) {
	if c.SessionID == "" || c.TenantID == "" {
		return nil, false, nil
	}
	sess, err := s.store.GetSession(ctx, c.SessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !sess.Active(s.now()) || sess.UserID != c.Subject || sess.TenantID != c.TenantID {
		return nil, false, nil
	}
	u, err := s.store.GetUser(ctx, c.TenantID, c.Subject)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if u.Status != domain.StatusActive {
		return nil, false, nil
	}
	ok, err := s.tenantActive(ctx, c.TenantID)
	return u, ok, err
}

// Authenticate resolves an access token into a Principal for Keyora's own
// API. Roles and permissions are read from the store, not the token, so
// revoking a session or a role takes effect immediately here.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (*Principal, error) {
	c, err := s.verifyJWT(accessToken)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	u, ok, err := s.liveUser(ctx, c)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, domain.ErrInvalidToken
	}
	roles, perms, err := s.rolesOf(ctx, u.TenantID, u.ID)
	if err != nil {
		return nil, err
	}
	return &Principal{UserID: u.ID, TenantID: u.TenantID, SessionID: c.SessionID, ClientID: c.ClientID, Roles: roles, Permissions: perms}, nil
}

// Introspect reports the live state of an access token to a confidential
// application of the same tenant. Any failure yields {"active": false}.
func (s *Service) Introspect(ctx context.Context, app *domain.Application, token string) (*Introspection, error) {
	inactive := &Introspection{Active: false}
	c, err := s.verifyJWT(token)
	if err != nil || c.TenantID != app.TenantID {
		return inactive, nil
	}
	out := &Introspection{Active: true, Subject: c.Subject, TenantID: c.TenantID, ClientID: c.ClientID,
		SessionID: c.SessionID, Issuer: c.Issuer, ExpiresAt: c.ExpiresAt, IssuedAt: c.IssuedAt}
	if c.SessionID == "" {
		// Client-credentials token: valid while its application is.
		owner, err := s.store.GetApplicationByClientID(ctx, c.ClientID)
		if errors.Is(err, domain.ErrNotFound) {
			return inactive, nil
		}
		if err != nil {
			return nil, err
		}
		if owner.Status != domain.StatusActive || owner.TenantID != app.TenantID || c.Subject != owner.ClientID {
			return inactive, nil
		}
		return out, nil
	}
	u, ok, err := s.liveUser(ctx, c)
	if err != nil {
		return nil, err
	}
	if !ok {
		return inactive, nil
	}
	out.Email = u.Email
	if out.Roles, out.Permissions, err = s.rolesOf(ctx, u.TenantID, u.ID); err != nil {
		return nil, err
	}
	return out, nil
}

// ClientCredentials issues a short-lived token that identifies the
// application itself. It carries no user, roles or refresh token.
func (s *Service) ClientCredentials(ctx context.Context, app *domain.Application, m Meta) (*Tokens, error) {
	now := s.now()
	access, err := s.keys.Signer().Sign(jwt.Claims{
		Issuer: s.opt.Issuer, Subject: app.ClientID, Audience: jwt.Audience{app.ClientID},
		ExpiresAt: now.Add(time.Duration(app.AccessTokenTTL) * time.Second).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
		ID: security.NewID(), TenantID: app.TenantID, ClientID: app.ClientID, TokenUse: jwt.UseAccess,
	})
	if err != nil {
		return nil, err
	}
	m.ActorType, m.ActorID = "application", app.ClientID
	s.audit(ctx, app.TenantID, "token.client_credentials", m, app.ID, nil)
	return &Tokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: app.AccessTokenTTL}, nil
}

// ---- email verification & password recovery ----

func link(template, token string) string {
	if template == "" {
		return ""
	}
	return strings.ReplaceAll(template, "{token}", token)
}

func (s *Service) newVerificationToken(ctx context.Context, u *domain.User, purpose, prefix string, ttl time.Duration) (string, error) {
	now := s.now()
	token := security.NewToken(prefix)
	err := s.store.CreateVerificationToken(ctx, &domain.VerificationToken{ID: security.NewID(), TenantID: u.TenantID, UserID: u.ID,
		Purpose: purpose, TokenHash: security.HashToken(token), CreatedAt: now, ExpiresAt: now.Add(ttl)})
	return token, err
}

func (s *Service) sendVerification(ctx context.Context, u *domain.User) {
	token, err := s.newVerificationToken(ctx, u, domain.PurposeEmailVerification, "kyv_", s.opt.EmailTokenTTL)
	if err != nil {
		s.log.Error("verification token not created", "user_id", u.ID, "error", err)
		return
	}
	body := "Confirm your email address with this verification token:\n\n" + token + "\n"
	if l := link(s.opt.EmailVerificationURL, token); l != "" {
		body = "Confirm your email address by opening this link:\n\n" + l + "\n"
	}
	s.deliver(ctx, mailer.Message{To: u.Email, Subject: "Verify your email address", Body: body})
}

// RequestEmailVerification re-sends the verification email. It reports
// success whether or not the address has an account.
func (s *Service) RequestEmailVerification(ctx context.Context, app *domain.Application, rawEmail string) error {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return err
	}
	u, err := s.store.GetUserByEmail(ctx, app.TenantID, email)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !u.EmailVerified && u.Status == domain.StatusActive {
		s.sendVerification(ctx, u)
	}
	return nil
}

// ConfirmEmail marks the address verified. The token is single use.
func (s *Service) ConfirmEmail(ctx context.Context, token string, m Meta) error {
	t, err := s.store.ConsumeVerificationToken(ctx, security.HashToken(token), domain.PurposeEmailVerification, s.now())
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ErrInvalidVerification
	}
	if err != nil {
		return err
	}
	u, err := s.store.GetUser(ctx, t.TenantID, t.UserID)
	if err != nil {
		return domain.ErrInvalidVerification
	}
	u.EmailVerified, u.UpdatedAt = true, s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	m.ActorType, m.ActorID = "user", u.ID
	s.audit(ctx, u.TenantID, "user.email.verified", m, u.ID, nil)
	return nil
}

// ForgotPassword emails a reset token. It reports success whether or not the
// address has an account.
func (s *Service) ForgotPassword(ctx context.Context, app *domain.Application, rawEmail string, m Meta) error {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return err
	}
	u, err := s.store.GetUserByEmail(ctx, app.TenantID, email)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if u.Status != domain.StatusActive {
		return nil
	}
	token, err := s.newVerificationToken(ctx, u, domain.PurposePasswordReset, "kyp_", s.opt.ResetTokenTTL)
	if err != nil {
		return err
	}
	body := "Reset your password with this token:\n\n" + token + "\n"
	if l := link(s.opt.PasswordResetURL, token); l != "" {
		body = "Reset your password by opening this link:\n\n" + l + "\n"
	}
	body += "\nIf you did not ask for this, you can ignore this email.\n"
	s.deliver(ctx, mailer.Message{To: u.Email, Subject: "Reset your password", Body: body})
	m.ActorType, m.ActorID = "user", u.ID
	s.audit(ctx, u.TenantID, "user.password.reset_requested", m, u.ID, nil)
	return nil
}

// ResetPassword sets a new password from a reset token and signs the user out everywhere.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string, m Meta) error {
	// Validate before consuming so a rejected password does not burn the token.
	if err := s.validatePassword(newPassword, ""); err != nil {
		return err
	}
	now := s.now()
	t, err := s.store.ConsumeVerificationToken(ctx, security.HashToken(token), domain.PurposePasswordReset, now)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ErrInvalidVerification
	}
	if err != nil {
		return err
	}
	u, err := s.store.GetUser(ctx, t.TenantID, t.UserID)
	if err != nil {
		return domain.ErrInvalidVerification
	}
	if err := s.setPassword(ctx, u, newPassword, true); err != nil {
		return err
	}
	if _, err := s.store.RevokeUserSessions(ctx, u.TenantID, u.ID, "", now); err != nil {
		return err
	}
	if err := s.store.ClearLoginFailures(ctx, u.TenantID, u.ID, nil); err != nil {
		return err
	}
	m.ActorType, m.ActorID = "user", u.ID
	s.audit(ctx, u.TenantID, "user.password.reset", m, u.ID, nil)
	return nil
}

func (s *Service) setPassword(ctx context.Context, u *domain.User, password string, markVerified bool) error {
	if err := s.validatePassword(password, u.Email); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return err
	}
	u.PasswordHash, u.UpdatedAt = hash, s.now()
	if markVerified {
		// Completing a reset proves control of the mailbox.
		u.EmailVerified = true
	}
	return s.store.UpdateUser(ctx, u)
}

// ChangePassword changes the caller's password and revokes their other sessions.
func (s *Service) ChangePassword(ctx context.Context, p *Principal, current, next string, m Meta) error {
	u, err := s.store.GetUser(ctx, p.TenantID, p.UserID)
	if err != nil {
		return err
	}
	if ok, _ := s.hasher.Verify(current, u.PasswordHash); !ok {
		return domain.E(domain.KindUnauthenticated, "invalid_credentials", "current password is incorrect")
	}
	if err := s.setPassword(ctx, u, next, false); err != nil {
		return err
	}
	if _, err := s.store.RevokeUserSessions(ctx, u.TenantID, u.ID, p.SessionID, s.now()); err != nil {
		return err
	}
	s.audit(ctx, u.TenantID, "user.password.changed", m, u.ID, nil)
	return nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
