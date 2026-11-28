package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/store"
)

// ---- tenants ----

type TenantInput struct {
	Slug   *string
	Name   *string
	Status *string
}

// CreateTenant creates a tenant and seeds its admin permission and role.
func (s *Service) CreateTenant(ctx context.Context, in TenantInput, m Meta) (*domain.Tenant, error) {
	if in.Slug == nil || !slugRe.MatchString(*in.Slug) {
		return nil, domain.Invalid("slug", "must be 2-63 lowercase letters, digits or hyphens")
	}
	name, err := validateDisplayName("name", deref(in.Name), true)
	if err != nil {
		return nil, err
	}
	now := s.now()
	t := &domain.Tenant{ID: security.NewID(), Slug: *in.Slug, Name: name, Status: domain.StatusActive, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateTenant(ctx, t); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "slug_taken", "a tenant with this slug already exists")
		}
		return nil, err
	}
	perm := &domain.Permission{ID: security.NewID(), TenantID: t.ID, Name: domain.PermissionAdmin,
		Description: "Manage this tenant's applications, users, roles and sessions", CreatedAt: now}
	role := &domain.Role{ID: security.NewID(), TenantID: t.ID, Name: domain.RoleAdmin,
		Description: "Tenant administrators", CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreatePermission(ctx, perm); err != nil {
		return nil, err
	}
	if err := s.store.CreateRole(ctx, role); err != nil {
		return nil, err
	}
	if err := s.store.SetRolePermissions(ctx, t.ID, role.ID, []string{perm.Name}); err != nil {
		return nil, err
	}
	s.audit(ctx, t.ID, "tenant.created", m, t.ID, nil)
	return t, nil
}

func (s *Service) GetTenant(ctx context.Context, id string) (*domain.Tenant, error) {
	return s.store.GetTenant(ctx, id)
}

func (s *Service) ListTenants(ctx context.Context, p store.Page) ([]*domain.Tenant, int, error) {
	return s.store.ListTenants(ctx, p)
}

func (s *Service) UpdateTenant(ctx context.Context, id string, in TenantInput, m Meta) (*domain.Tenant, error) {
	t, err := s.store.GetTenant(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if t.Name, err = validateDisplayName("name", *in.Name, true); err != nil {
			return nil, err
		}
	}
	if in.Status != nil {
		if *in.Status != domain.StatusActive && *in.Status != domain.StatusSuspended {
			return nil, domain.Invalid("status", "must be active or suspended")
		}
		t.Status = *in.Status
	}
	t.UpdatedAt = s.now()
	if err := s.store.UpdateTenant(ctx, t); err != nil {
		return nil, err
	}
	s.audit(ctx, t.ID, "tenant.updated", m, t.ID, map[string]string{"status": t.Status})
	return t, nil
}

// ---- applications ----

type ApplicationInput struct {
	Name            *string
	Type            *string
	RedirectURIs    *[]string
	AllowedOrigins  *[]string
	AccessTokenTTL  *int64
	RefreshTokenTTL *int64
	Status          *string
}

func (s *Service) applyAppInput(a *domain.Application, in ApplicationInput) (err error) {
	if in.Name != nil {
		if a.Name, err = validateDisplayName("name", *in.Name, true); err != nil {
			return err
		}
	}
	if in.RedirectURIs != nil {
		if a.RedirectURIs, err = validateRedirectURIs(*in.RedirectURIs); err != nil {
			return err
		}
	}
	if in.AllowedOrigins != nil {
		if a.AllowedOrigins, err = validateOrigins(*in.AllowedOrigins); err != nil {
			return err
		}
	}
	if in.AccessTokenTTL != nil {
		a.AccessTokenTTL = *in.AccessTokenTTL
	}
	if in.RefreshTokenTTL != nil {
		a.RefreshTokenTTL = *in.RefreshTokenTTL
	}
	if a.AccessTokenTTL < 60 || a.AccessTokenTTL > 86400 {
		return domain.Invalid("access_token_ttl_seconds", "must be between 60 and 86400")
	}
	if a.RefreshTokenTTL <= a.AccessTokenTTL || a.RefreshTokenTTL > 365*86400 {
		return domain.Invalid("refresh_token_ttl_seconds", "must be longer than the access token TTL and at most one year")
	}
	if in.Status != nil {
		if *in.Status != domain.StatusActive && *in.Status != domain.StatusDisabled {
			return domain.Invalid("status", "must be active or disabled")
		}
		a.Status = *in.Status
	}
	return nil
}

// CreateApplication registers an application. For confidential applications
// the returned secret is shown exactly once; only its hash is stored.
func (s *Service) CreateApplication(ctx context.Context, tenantID string, in ApplicationInput, m Meta) (*domain.Application, string, error) {
	typ := deref(in.Type)
	if typ == "" {
		typ = domain.AppConfidential
	}
	if typ != domain.AppConfidential && typ != domain.AppPublic {
		return nil, "", domain.Invalid("type", "must be confidential or public")
	}
	if in.Name == nil {
		return nil, "", domain.Invalid("name", "is required")
	}
	now := s.now()
	a := &domain.Application{ID: security.NewID(), TenantID: tenantID, Type: typ,
		ClientID:     "app_" + strings.ReplaceAll(security.NewID(), "-", ""),
		RedirectURIs: []string{}, AllowedOrigins: []string{},
		AccessTokenTTL: int64(s.opt.AccessTokenTTL.Seconds()), RefreshTokenTTL: int64(s.opt.RefreshTokenTTL.Seconds()),
		Status: domain.StatusActive, CreatedAt: now, UpdatedAt: now}
	in.Status = nil
	if err := s.applyAppInput(a, in); err != nil {
		return nil, "", err
	}
	secret := ""
	if typ == domain.AppConfidential {
		secret = security.NewToken("kys_")
		a.ClientSecretHash = security.HashToken(secret)
	}
	if err := s.store.CreateApplication(ctx, a); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, "", domain.E(domain.KindConflict, "name_taken", "an application with this name already exists in the tenant")
		}
		return nil, "", err
	}
	s.originsVersion.Add(1)
	s.audit(ctx, tenantID, "application.created", m, a.ID, map[string]string{"client_id": a.ClientID, "type": a.Type})
	return a, secret, nil
}

func (s *Service) GetApplication(ctx context.Context, tenantID, id string) (*domain.Application, error) {
	return s.store.GetApplication(ctx, tenantID, id)
}

func (s *Service) ListApplications(ctx context.Context, tenantID string, p store.Page) ([]*domain.Application, int, error) {
	return s.store.ListApplications(ctx, tenantID, p)
}

func (s *Service) UpdateApplication(ctx context.Context, tenantID, id string, in ApplicationInput, m Meta) (*domain.Application, error) {
	a, err := s.store.GetApplication(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if in.Type != nil && *in.Type != a.Type {
		return nil, domain.Invalid("type", "cannot be changed after creation")
	}
	if err := s.applyAppInput(a, in); err != nil {
		return nil, err
	}
	a.UpdatedAt = s.now()
	if err := s.store.UpdateApplication(ctx, a); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "name_taken", "an application with this name already exists in the tenant")
		}
		return nil, err
	}
	s.originsVersion.Add(1)
	s.audit(ctx, tenantID, "application.updated", m, a.ID, nil)
	return a, nil
}

func (s *Service) DeleteApplication(ctx context.Context, tenantID, id string, m Meta) error {
	if err := s.store.DeleteApplication(ctx, tenantID, id); err != nil {
		return err
	}
	s.originsVersion.Add(1)
	s.audit(ctx, tenantID, "application.deleted", m, id, nil)
	return nil
}

// RotateApplicationSecret replaces the client secret; the old one stops working immediately.
func (s *Service) RotateApplicationSecret(ctx context.Context, tenantID, id string, m Meta) (*domain.Application, string, error) {
	a, err := s.store.GetApplication(ctx, tenantID, id)
	if err != nil {
		return nil, "", err
	}
	if a.Type != domain.AppConfidential {
		return nil, "", domain.E(domain.KindInvalid, "not_confidential", "public applications have no client secret")
	}
	secret := security.NewToken("kys_")
	a.ClientSecretHash, a.UpdatedAt = security.HashToken(secret), s.now()
	if err := s.store.UpdateApplication(ctx, a); err != nil {
		return nil, "", err
	}
	s.audit(ctx, tenantID, "application.secret_rotated", m, a.ID, nil)
	return a, secret, nil
}

// OriginsVersion changes every time an application is created, updated or
// deleted through this service, whichever transport made the change. A cache
// of AllowedOrigins reloads when it sees a new value. (Other instances of
// Keyora are not notified; their caches expire on their own schedule.)
func (s *Service) OriginsVersion() uint64 { return s.originsVersion.Load() }

// AllowedOrigins lists every origin registered on an active application.
func (s *Service) AllowedOrigins(ctx context.Context) ([]string, error) {
	return s.store.ListAllowedOrigins(ctx)
}

// ---- users ----

type UserInput struct {
	Email         *string
	Password      *string
	Name          *string
	Status        *string
	EmailVerified *bool
}

// AdminCreateUser creates a user on behalf of an administrator.
func (s *Service) AdminCreateUser(ctx context.Context, tenantID string, in UserInput, m Meta) (*domain.User, error) {
	if _, err := s.store.GetTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	u, err := s.createUser(ctx, tenantID, deref(in.Email), deref(in.Password), deref(in.Name), in.EmailVerified != nil && *in.EmailVerified)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, tenantID, "user.created", m, u.ID, nil)
	return u, nil
}

func (s *Service) GetUser(ctx context.Context, tenantID, id string) (*domain.User, error) {
	return s.store.GetUser(ctx, tenantID, id)
}

func (s *Service) ListUsers(ctx context.Context, tenantID string, f store.UserFilter, p store.Page) ([]*domain.User, int, error) {
	return s.store.ListUsers(ctx, tenantID, f, p)
}

// UpdateUser edits profile fields. Disabling a user revokes all their sessions.
func (s *Service) UpdateUser(ctx context.Context, tenantID, id string, in UserInput, m Meta) (*domain.User, error) {
	u, err := s.store.GetUser(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if u.Name, err = validateDisplayName("name", *in.Name, false); err != nil {
			return nil, err
		}
	}
	if in.EmailVerified != nil {
		u.EmailVerified = *in.EmailVerified
	}
	disabled := false
	if in.Status != nil {
		if *in.Status != domain.StatusActive && *in.Status != domain.StatusDisabled {
			return nil, domain.Invalid("status", "must be active or disabled")
		}
		disabled = *in.Status == domain.StatusDisabled && u.Status != domain.StatusDisabled
		u.Status = *in.Status
	}
	u.UpdatedAt = s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return nil, err
	}
	if disabled {
		if _, err := s.store.RevokeUserSessions(ctx, tenantID, id, "", s.now()); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, tenantID, "user.updated", m, u.ID, map[string]string{"status": u.Status})
	return u, nil
}

func (s *Service) DeleteUser(ctx context.Context, tenantID, id string, m Meta) error {
	if err := s.store.DeleteUser(ctx, tenantID, id); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "user.deleted", m, id, nil)
	return nil
}

// UnlockUser clears a brute-force lockout.
func (s *Service) UnlockUser(ctx context.Context, tenantID, id string, m Meta) (*domain.User, error) {
	if err := s.store.ClearLoginFailures(ctx, tenantID, id, nil); err != nil {
		return nil, err
	}
	s.audit(ctx, tenantID, "user.unlocked", m, id, nil)
	return s.store.GetUser(ctx, tenantID, id)
}

// ---- permissions & roles ----

func (s *Service) CreatePermission(ctx context.Context, tenantID, name, description string, m Meta) (*domain.Permission, error) {
	if !nameRe.MatchString(name) {
		return nil, domain.Invalid("name", "must be 1-100 letters, digits, ':', '_', '.' or '-'")
	}
	if strings.HasPrefix(strings.ToLower(name), "keyora:") {
		return nil, domain.Invalid("name", "the keyora: prefix is reserved")
	}
	description, err := validateText("description", description, 500)
	if err != nil {
		return nil, err
	}
	p := &domain.Permission{ID: security.NewID(), TenantID: tenantID, Name: name, Description: description, CreatedAt: s.now()}
	if err := s.store.CreatePermission(ctx, p); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "name_taken", "a permission with this name already exists")
		}
		return nil, err
	}
	s.audit(ctx, tenantID, "permission.created", m, p.ID, map[string]string{"name": p.Name})
	return p, nil
}

func (s *Service) ListPermissions(ctx context.Context, tenantID string, p store.Page) ([]*domain.Permission, int, error) {
	return s.store.ListPermissions(ctx, tenantID, p)
}

func (s *Service) DeletePermission(ctx context.Context, tenantID, id string, m Meta) error {
	all, _, err := s.store.ListPermissions(ctx, tenantID, store.Page{})
	if err != nil {
		return err
	}
	for _, p := range all {
		if p.ID == id && p.Name == domain.PermissionAdmin {
			return domain.E(domain.KindForbidden, "reserved", "the built-in admin permission cannot be deleted")
		}
	}
	if err := s.store.DeletePermission(ctx, tenantID, id); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "permission.deleted", m, id, nil)
	return nil
}

func (s *Service) CreateRole(ctx context.Context, tenantID, name, description string, permissions []string, m Meta) (*domain.Role, error) {
	if !nameRe.MatchString(name) {
		return nil, domain.Invalid("name", "must be 1-100 letters, digits, ':', '_', '.' or '-'")
	}
	description, err := validateText("description", description, 500)
	if err != nil {
		return nil, err
	}
	now := s.now()
	r := &domain.Role{ID: security.NewID(), TenantID: tenantID, Name: name, Description: description, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateRole(ctx, r); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "name_taken", "a role with this name already exists")
		}
		return nil, err
	}
	if len(permissions) > 0 {
		if err := s.setRolePermissions(ctx, tenantID, r.ID, permissions); err != nil {
			_ = s.store.DeleteRole(ctx, tenantID, r.ID)
			return nil, err
		}
	}
	s.audit(ctx, tenantID, "role.created", m, r.ID, map[string]string{"name": r.Name})
	return s.store.GetRole(ctx, tenantID, r.ID)
}

func (s *Service) setRolePermissions(ctx context.Context, tenantID, roleID string, names []string) error {
	err := s.store.SetRolePermissions(ctx, tenantID, roleID, names)
	if errors.Is(err, domain.ErrNotFound) {
		if _, rerr := s.store.GetRole(ctx, tenantID, roleID); rerr != nil {
			return rerr
		}
		return domain.Invalid("permissions", "every permission must already exist in this tenant")
	}
	return err
}

func (s *Service) GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error) {
	return s.store.GetRole(ctx, tenantID, id)
}

func (s *Service) ListRoles(ctx context.Context, tenantID string, p store.Page) ([]*domain.Role, int, error) {
	return s.store.ListRoles(ctx, tenantID, p)
}

func (s *Service) UpdateRole(ctx context.Context, tenantID, id string, name, description *string, m Meta) (*domain.Role, error) {
	r, err := s.store.GetRole(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if name != nil && *name != r.Name {
		if r.Name == domain.RoleAdmin {
			return nil, domain.E(domain.KindForbidden, "reserved", "the built-in admin role cannot be renamed")
		}
		if !nameRe.MatchString(*name) {
			return nil, domain.Invalid("name", "must be 1-100 letters, digits, ':', '_', '.' or '-'")
		}
		r.Name = *name
	}
	if description != nil {
		if r.Description, err = validateText("description", *description, 500); err != nil {
			return nil, err
		}
	}
	r.UpdatedAt = s.now()
	if err := s.store.UpdateRole(ctx, r); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.KindConflict, "name_taken", "a role with this name already exists")
		}
		return nil, err
	}
	s.audit(ctx, tenantID, "role.updated", m, r.ID, nil)
	return r, nil
}

func (s *Service) DeleteRole(ctx context.Context, tenantID, id string, m Meta) error {
	r, err := s.store.GetRole(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if r.Name == domain.RoleAdmin {
		return domain.E(domain.KindForbidden, "reserved", "the built-in admin role cannot be deleted")
	}
	if err := s.store.DeleteRole(ctx, tenantID, id); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "role.deleted", m, id, map[string]string{"name": r.Name})
	return nil
}

func (s *Service) SetRolePermissions(ctx context.Context, tenantID, roleID string, names []string, m Meta) (*domain.Role, error) {
	r, err := s.store.GetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if r.Name == domain.RoleAdmin && !containsString(names, domain.PermissionAdmin) {
		return nil, domain.E(domain.KindForbidden, "reserved", "the built-in admin role must keep the keyora:admin permission")
	}
	if err := s.setRolePermissions(ctx, tenantID, roleID, names); err != nil {
		return nil, err
	}
	s.audit(ctx, tenantID, "role.permissions_set", m, roleID, map[string]string{"permissions": strings.Join(names, " ")})
	return s.store.GetRole(ctx, tenantID, roleID)
}

func (s *Service) AssignRole(ctx context.Context, tenantID, userID, roleID string, m Meta) error {
	if err := s.store.AssignRole(ctx, tenantID, userID, roleID, s.now()); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "user.role.assigned", m, userID, map[string]string{"role_id": roleID})
	return nil
}

func (s *Service) UnassignRole(ctx context.Context, tenantID, userID, roleID string, m Meta) error {
	if err := s.store.UnassignRole(ctx, tenantID, userID, roleID); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "user.role.unassigned", m, userID, map[string]string{"role_id": roleID})
	return nil
}

func (s *Service) ListUserRoles(ctx context.Context, tenantID, userID string) ([]*domain.Role, error) {
	if _, err := s.store.GetUser(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	return s.store.ListUserRoles(ctx, tenantID, userID)
}

// ---- sessions & audit ----

func (s *Service) ListSessions(ctx context.Context, tenantID, userID string, activeOnly bool, p store.Page) ([]*domain.Session, int, error) {
	return s.store.ListSessions(ctx, tenantID, store.SessionFilter{UserID: userID, ActiveOnly: activeOnly, Now: s.now()}, p)
}

// RevokeSession revokes a session of the tenant. A non-empty userID further
// restricts it to that user's sessions, which is how self-service is scoped.
func (s *Service) RevokeSession(ctx context.Context, tenantID, userID, sessionID string, m Meta) error {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if sess.TenantID != tenantID || (userID != "" && sess.UserID != userID) {
		return domain.ErrNotFound
	}
	return s.revokeSession(ctx, sess, m, "session.revoked")
}

func (s *Service) ListAuditEvents(ctx context.Context, tenantID string, f store.AuditFilter, p store.Page) ([]*domain.AuditEvent, int, error) {
	return s.store.ListAuditEvents(ctx, tenantID, f, p)
}

// PurgeExpired deletes expired tokens and sessions.
func (s *Service) PurgeExpired(ctx context.Context) (int, error) {
	// Keep a day of history so reuse of a just-expired token is still recognised.
	return s.store.DeleteExpired(ctx, s.now().Add(-24*time.Hour))
}

// UpdateProfile lets a user change their own display name.
func (s *Service) UpdateProfile(ctx context.Context, p *Principal, name string, m Meta) (*domain.User, error) {
	return s.UpdateUser(ctx, p.TenantID, p.UserID, UserInput{Name: &name}, m)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
