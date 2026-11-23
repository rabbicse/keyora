// Package store defines the persistence contract the identity core depends on.
// Implementations live in subpackages; none of them leak into domain logic.
package store

import (
	"context"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
)

type Page struct {
	Limit  int
	Offset int
}

type UserFilter struct {
	Email  string
	Status string
}

type SessionFilter struct {
	UserID     string
	ActiveOnly bool
	Now        time.Time
}

type AuditFilter struct {
	Type    string
	ActorID string
}

// Store is the single persistence port. Every tenant-owned read and write takes
// the tenant ID so isolation is enforced at the lowest layer, not by callers
// remembering to filter. Methods return domain.ErrNotFound / domain.ErrConflict.
type Store interface {
	Ping(ctx context.Context) error
	Close() error

	CreateTenant(ctx context.Context, t *domain.Tenant) error
	GetTenant(ctx context.Context, id string) (*domain.Tenant, error)
	ListTenants(ctx context.Context, p Page) ([]*domain.Tenant, int, error)
	UpdateTenant(ctx context.Context, t *domain.Tenant) error

	CreateApplication(ctx context.Context, a *domain.Application) error
	GetApplication(ctx context.Context, tenantID, id string) (*domain.Application, error)
	GetApplicationByClientID(ctx context.Context, clientID string) (*domain.Application, error)
	ListApplications(ctx context.Context, tenantID string, p Page) ([]*domain.Application, int, error)
	UpdateApplication(ctx context.Context, a *domain.Application) error
	DeleteApplication(ctx context.Context, tenantID, id string) error
	ListAllowedOrigins(ctx context.Context) ([]string, error)

	CreateUser(ctx context.Context, u *domain.User) error
	GetUser(ctx context.Context, tenantID, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (*domain.User, error)
	ListUsers(ctx context.Context, tenantID string, f UserFilter, p Page) ([]*domain.User, int, error)
	// UpdateUser writes profile and credential fields. Lockout counters are
	// only changed through the dedicated atomic methods below.
	UpdateUser(ctx context.Context, u *domain.User) error
	DeleteUser(ctx context.Context, tenantID, id string) error
	IncrementFailedLogins(ctx context.Context, tenantID, userID string) (int, error)
	LockUser(ctx context.Context, tenantID, userID string, until time.Time) error
	// ClearLoginFailures resets the counter and lock; a non-nil lastLogin is recorded.
	ClearLoginFailures(ctx context.Context, tenantID, userID string, lastLogin *time.Time) error

	CreatePermission(ctx context.Context, p *domain.Permission) error
	ListPermissions(ctx context.Context, tenantID string, p Page) ([]*domain.Permission, int, error)
	DeletePermission(ctx context.Context, tenantID, id string) error

	CreateRole(ctx context.Context, r *domain.Role) error
	GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error)
	ListRoles(ctx context.Context, tenantID string, p Page) ([]*domain.Role, int, error)
	UpdateRole(ctx context.Context, r *domain.Role) error
	DeleteRole(ctx context.Context, tenantID, id string) error
	// SetRolePermissions replaces the role's permissions. Every name must
	// exist in the tenant's catalogue, otherwise domain.ErrNotFound.
	SetRolePermissions(ctx context.Context, tenantID, roleID string, names []string) error
	AssignRole(ctx context.Context, tenantID, userID, roleID string, at time.Time) error
	UnassignRole(ctx context.Context, tenantID, userID, roleID string) error
	ListUserRoles(ctx context.Context, tenantID, userID string) ([]*domain.Role, error)

	CreateSession(ctx context.Context, s *domain.Session) error
	GetSession(ctx context.Context, id string) (*domain.Session, error)
	ListSessions(ctx context.Context, tenantID string, f SessionFilter, p Page) ([]*domain.Session, int, error)
	TouchSession(ctx context.Context, id string, lastUsed, expires time.Time) error
	RevokeSession(ctx context.Context, id string, at time.Time) error
	RevokeUserSessions(ctx context.Context, tenantID, userID, exceptSessionID string, at time.Time) (int, error)

	CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error)
	// ConsumeRefreshToken atomically marks the token used. reused is true when
	// it had already been used, which signals token theft to the caller.
	ConsumeRefreshToken(ctx context.Context, hash string, at time.Time) (t *domain.RefreshToken, reused bool, err error)

	CreateVerificationToken(ctx context.Context, t *domain.VerificationToken) error
	// ConsumeVerificationToken atomically marks an unused, unexpired token used.
	ConsumeVerificationToken(ctx context.Context, hash, purpose string, at time.Time) (*domain.VerificationToken, error)

	CreateAuthorizationCode(ctx context.Context, c *domain.AuthorizationCode) error
	// ConsumeAuthorizationCode atomically marks the code used. reused is true
	// when it had already been redeemed, which the caller treats as an attack.
	ConsumeAuthorizationCode(ctx context.Context, hash string, at time.Time) (c *domain.AuthorizationCode, reused bool, err error)

	CreateLegacyCredential(ctx context.Context, c *domain.LegacyCredential) error
	GetLegacyCredential(ctx context.Context, tenantID, username string) (*domain.LegacyCredential, error)

	AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, tenantID string, f AuditFilter, p Page) ([]*domain.AuditEvent, int, error)

	// DeleteExpired removes expired tokens, authorization codes and sessions.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
