package domain

import "time"

const (
	StatusActive    = "active"
	StatusDisabled  = "disabled"
	StatusSuspended = "suspended"

	AppConfidential = "confidential"
	AppPublic       = "public"

	PurposeEmailVerification = "email_verification"
	PurposePasswordReset     = "password_reset"

	// PermissionAdmin grants management access to the holder's own tenant.
	PermissionAdmin = "keyora:admin"
	// RoleAdmin is seeded into every tenant and carries PermissionAdmin.
	RoleAdmin = "keyora-admin"
)

// Tenant is the isolation boundary: users, applications, roles and sessions
// all belong to exactly one tenant.
type Tenant struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Application is a registered client of a tenant. Users are not owned by an
// application; any application in a tenant can sign in that tenant's users.
type Application struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	RedirectURIs     []string  `json:"redirect_uris"`
	AllowedOrigins   []string  `json:"allowed_origins"`
	AccessTokenTTL   int64     `json:"access_token_ttl_seconds"`
	RefreshTokenTTL  int64     `json:"refresh_token_ttl_seconds"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type User struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	PasswordHash  string     `json:"-"`
	Status        string     `json:"status"`
	EmailVerified bool       `json:"email_verified"`
	FailedLogins  int        `json:"-"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type Permission struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Session is one sign-in on one device. Refresh tokens rotate inside it.
type Session struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	UserID        string     `json:"user_id"`
	ApplicationID string     `json:"application_id"`
	IP            string     `json:"ip"`
	UserAgent     string     `json:"user_agent"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    time.Time  `json:"last_used_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the session can still be used at the given time.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// RefreshToken stores only the SHA-256 of the opaque token handed to clients.
type RefreshToken struct {
	ID        string
	SessionID string
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// VerificationToken backs email verification and password reset links.
type VerificationToken struct {
	ID        string
	TenantID  string
	UserID    string
	Purpose   string
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type AuditEvent struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Type      string            `json:"type"`
	ActorType string            `json:"actor_type"`
	ActorID   string            `json:"actor_id"`
	TargetID  string            `json:"target_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// AuthorizationCode is a pending OAuth 2.0 authorization code. Only the
// SHA-256 of the code is stored. It is bound to the application, redirect URI
// and PKCE challenge it was issued for, and to the session opened at sign-in.
type AuthorizationCode struct {
	ID            string
	CodeHash      string
	TenantID      string
	ApplicationID string
	UserID        string
	SessionID     string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Nonce         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

// LegacyCredential holds the salt and verifier of a user registered through
// the tutorial-compatibility API. The verifier is password-equivalent: anyone
// who reads it can log in as the user. It exists only so clients written for
// the original tutorial keep working; see docs/legacy-tutorial-api.md.
type LegacyCredential struct {
	UserID    string
	TenantID  string
	Username  string
	Salt      []byte
	Verifier  []byte
	CreatedAt time.Time
}
