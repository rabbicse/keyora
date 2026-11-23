// Package service implements Keyora's use cases. It depends on the storage
// port, the key ring and a mailer, and knows nothing about HTTP.
package service

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/mailer"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/store"
)

// Options tunes policy. Zero values fall back to safe defaults.
type Options struct {
	Issuer                   string
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	PasswordMinLength        int
	PBKDF2Iterations         int
	MaxFailedLogins          int
	LockoutDuration          time.Duration
	RequireEmailVerification bool
	EmailVerificationURL     string
	PasswordResetURL         string
	EmailTokenTTL            time.Duration
	ResetTokenTTL            time.Duration
	// SynchronousMail sends email inline instead of in the background.
	SynchronousMail bool
	Clock           func() time.Time
}

// Meta carries request context into the audit trail.
type Meta struct {
	IP        string
	UserAgent string
	RequestID string
	ActorType string // "user", "application", "root", "anonymous"
	ActorID   string
}

type Service struct {
	store  store.Store
	keys   *security.KeyRing
	hasher security.PasswordHasher
	mail   mailer.Mailer
	opt    Options
	log    *slog.Logger
	// dummyHash is verified against when a login names an unknown user, so
	// both paths cost one PBKDF2 computation and do not differ in timing.
	dummyHash string
	legacy    *legacyState
}

func New(st store.Store, keys *security.KeyRing, mail mailer.Mailer, opt Options, log *slog.Logger) (*Service, error) {
	if opt.Issuer == "" {
		return nil, errors.New("service: issuer is required")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&opt.AccessTokenTTL, 15*time.Minute)
	def(&opt.RefreshTokenTTL, 30*24*time.Hour)
	def(&opt.LockoutDuration, 15*time.Minute)
	def(&opt.EmailTokenTTL, 24*time.Hour)
	def(&opt.ResetTokenTTL, time.Hour)
	if opt.PasswordMinLength < 8 {
		opt.PasswordMinLength = 8
	}
	if opt.MaxFailedLogins < 1 {
		opt.MaxFailedLogins = 5
	}
	if opt.Clock == nil {
		opt.Clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Service{store: st, keys: keys, mail: mail, opt: opt, log: log, legacy: newLegacyState(),
		hasher: security.PasswordHasher{Iterations: opt.PBKDF2Iterations}}
	h, err := s.hasher.Hash(security.NewToken(""))
	if err != nil {
		return nil, err
	}
	s.dummyHash = h
	return s, nil
}

func (s *Service) now() time.Time { return s.opt.Clock().UTC().Truncate(time.Millisecond) }

// Store exposes the underlying store for health checks.
func (s *Service) Store() store.Store { return s.store }

// Issuer returns the configured issuer identifier.
func (s *Service) Issuer() string { return s.opt.Issuer }

// Keys exposes the key ring for the JWKS endpoint.
func (s *Service) Keys() *security.KeyRing { return s.keys }

// audit records a security event. Failing to write the trail must not turn a
// successful operation into an error, so failures are logged instead.
func (s *Service) audit(ctx context.Context, tenantID, typ string, m Meta, targetID string, md map[string]string) {
	if m.ActorType == "" {
		m.ActorType = "anonymous"
	}
	e := &domain.AuditEvent{
		ID: security.NewID(), TenantID: tenantID, Type: typ, ActorType: m.ActorType, ActorID: m.ActorID,
		TargetID: targetID, IP: m.IP, UserAgent: truncate(m.UserAgent, 256), RequestID: m.RequestID,
		Metadata: md, CreatedAt: s.now(),
	}
	if err := s.store.AppendAuditEvent(context.WithoutCancel(ctx), e); err != nil {
		s.log.Error("audit event not recorded", "type", typ, "tenant_id", tenantID, "error", err)
	}
}

func (s *Service) deliver(ctx context.Context, msg mailer.Message) {
	send := func(ctx context.Context) {
		if err := s.mail.Send(ctx, msg); err != nil {
			s.log.Error("email delivery failed", "subject", msg.Subject, "error", err)
		}
	}
	if s.opt.SynchronousMail {
		send(ctx)
		return
	}
	// Sent in the background so response time does not reveal whether the
	// address belongs to an account.
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		send(bg)
	}()
}

// ---- validation ----

var (
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.\-]{0,99}$`)
)

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 254 {
		return "", domain.Invalid("email", "must be a valid email address")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", domain.Invalid("email", "must be a valid email address")
	}
	return email, nil
}

func (s *Service) validatePassword(password, email string) error {
	switch {
	case len([]rune(password)) < s.opt.PasswordMinLength:
		return domain.Invalid("password", "must be at least "+itoa(s.opt.PasswordMinLength)+" characters")
	case len(password) > security.MaxPasswordBytes:
		return domain.Invalid("password", "must be at most "+itoa(security.MaxPasswordBytes)+" bytes")
	case email != "" && strings.EqualFold(password, email):
		return domain.Invalid("password", "must not be the same as the email address")
	}
	return nil
}

func validateDisplayName(field, v string, required bool) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" && required {
		return "", domain.Invalid(field, "is required")
	}
	if len(v) > 200 {
		return "", domain.Invalid(field, "must be at most 200 characters")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", domain.Invalid(field, "must not contain control characters")
		}
	}
	return v, nil
}

// validateText bounds free-form text and rejects control characters (which
// includes NUL, something PostgreSQL cannot store).
func validateText(field, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return "", domain.Invalid(field, "must be at most "+itoa(max)+" characters")
	}
	for _, r := range v {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return "", domain.Invalid(field, "must not contain control characters")
		}
	}
	return v, nil
}

func validateOrigins(origins []string) ([]string, error) {
	out := []string{}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, domain.Invalid("allowed_origins", "each origin must look like https://app.example.com with no path")
		}
		out = append(out, u.Scheme+"://"+u.Host)
	}
	if len(out) > 50 {
		return nil, domain.Invalid("allowed_origins", "at most 50 origins")
	}
	return out, nil
}

func validateRedirectURIs(uris []string) ([]string, error) {
	out := []string{}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Fragment != "" || strings.Contains(raw, "*") ||
			((u.Scheme == "http" || u.Scheme == "https") && u.Host == "") {
			return nil, domain.Invalid("redirect_uris", "each URI must be absolute, without fragment or wildcard")
		}
		out = append(out, raw)
	}
	if len(out) > 50 {
		return nil, domain.Invalid("redirect_uris", "at most 50 redirect URIs")
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
