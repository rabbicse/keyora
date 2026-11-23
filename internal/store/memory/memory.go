// Package memory is an in-process Store used for tests and throwaway
// development servers. Data is lost when the process exits.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/store"
)

type Store struct {
	mu          sync.Mutex
	tenants     map[string]*domain.Tenant
	apps        map[string]*domain.Application
	users       map[string]*domain.User
	permissions map[string]*domain.Permission
	roles       map[string]*domain.Role
	userRoles   map[string]map[string]bool // userID -> roleID
	sessions    map[string]*domain.Session
	refresh     map[string]*domain.RefreshToken      // by hash
	verify      map[string]*domain.VerificationToken // by hash
	codes       map[string]*domain.AuthorizationCode // by hash
	legacy      map[string]*domain.LegacyCredential  // by user ID
	audit       []*domain.AuditEvent
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		tenants:     map[string]*domain.Tenant{},
		apps:        map[string]*domain.Application{},
		users:       map[string]*domain.User{},
		permissions: map[string]*domain.Permission{},
		roles:       map[string]*domain.Role{},
		userRoles:   map[string]map[string]bool{},
		sessions:    map[string]*domain.Session{},
		refresh:     map[string]*domain.RefreshToken{},
		verify:      map[string]*domain.VerificationToken{},
		codes:       map[string]*domain.AuthorizationCode{},
		legacy:      map[string]*domain.LegacyCredential{},
	}
}

func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close() error               { return nil }

// ---- helpers ----

func timePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneApp(a *domain.Application) *domain.Application {
	c := *a
	c.RedirectURIs = append([]string{}, a.RedirectURIs...)
	c.AllowedOrigins = append([]string{}, a.AllowedOrigins...)
	return &c
}

func cloneUser(u *domain.User) *domain.User {
	c := *u
	c.LockedUntil, c.LastLoginAt = timePtr(u.LockedUntil), timePtr(u.LastLoginAt)
	return &c
}

func cloneRole(r *domain.Role) *domain.Role {
	c := *r
	c.Permissions = append([]string{}, r.Permissions...)
	return &c
}

func cloneSession(x *domain.Session) *domain.Session {
	c := *x
	c.RevokedAt = timePtr(x.RevokedAt)
	return &c
}

// page sorts items newest-first (ties broken by ID) and slices out one page.
func page[T any](items []T, p store.Page, created func(T) time.Time, id func(T) string) ([]T, int) {
	sort.Slice(items, func(i, j int) bool {
		ci, cj := created(items[i]), created(items[j])
		if !ci.Equal(cj) {
			return ci.After(cj)
		}
		return id(items[i]) < id(items[j])
	})
	total := len(items)
	if p.Offset >= total {
		return []T{}, total
	}
	end := total
	if p.Limit > 0 && p.Offset+p.Limit < total {
		end = p.Offset + p.Limit
	}
	return items[p.Offset:end], total
}

// ---- tenants ----

func (s *Store) CreateTenant(_ context.Context, t *domain.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.tenants {
		if x.Slug == t.Slug {
			return domain.ErrConflict
		}
	}
	c := *t
	s.tenants[t.ID] = &c
	return nil
}

func (s *Store) GetTenant(_ context.Context, id string) (*domain.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *t
	return &c, nil
}

func (s *Store) ListTenants(_ context.Context, p store.Page) ([]*domain.Tenant, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.Tenant
	for _, t := range s.tenants {
		c := *t
		all = append(all, &c)
	}
	out, total := page(all, p, func(t *domain.Tenant) time.Time { return t.CreatedAt }, func(t *domain.Tenant) string { return t.ID })
	return out, total, nil
}

func (s *Store) UpdateTenant(_ context.Context, t *domain.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[t.ID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range s.tenants {
		if x.Slug == t.Slug && x.ID != t.ID {
			return domain.ErrConflict
		}
	}
	c := *t
	s.tenants[t.ID] = &c
	return nil
}

// ---- applications ----

func (s *Store) CreateApplication(_ context.Context, a *domain.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[a.TenantID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range s.apps {
		if x.ClientID == a.ClientID || (x.TenantID == a.TenantID && x.Name == a.Name) {
			return domain.ErrConflict
		}
	}
	s.apps[a.ID] = cloneApp(a)
	return nil
}

func (s *Store) GetApplication(_ context.Context, tenantID, id string) (*domain.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[id]
	if !ok || a.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	return cloneApp(a), nil
}

func (s *Store) GetApplicationByClientID(_ context.Context, clientID string) (*domain.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if a.ClientID == clientID {
			return cloneApp(a), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) ListApplications(_ context.Context, tenantID string, p store.Page) ([]*domain.Application, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.Application
	for _, a := range s.apps {
		if a.TenantID == tenantID {
			all = append(all, cloneApp(a))
		}
	}
	out, total := page(all, p, func(a *domain.Application) time.Time { return a.CreatedAt }, func(a *domain.Application) string { return a.ID })
	return out, total, nil
}

func (s *Store) UpdateApplication(_ context.Context, a *domain.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.apps[a.ID]
	if !ok || cur.TenantID != a.TenantID {
		return domain.ErrNotFound
	}
	for _, x := range s.apps {
		if x.ID != a.ID && x.TenantID == a.TenantID && x.Name == a.Name {
			return domain.ErrConflict
		}
	}
	s.apps[a.ID] = cloneApp(a)
	return nil
}

func (s *Store) DeleteApplication(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[id]
	if !ok || a.TenantID != tenantID {
		return domain.ErrNotFound
	}
	delete(s.apps, id)
	for sid, sess := range s.sessions {
		if sess.ApplicationID == id {
			s.deleteSessionLocked(sid)
		}
	}
	return nil
}

func (s *Store) ListAllowedOrigins(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, a := range s.apps {
		if a.Status != domain.StatusActive {
			continue
		}
		for _, o := range a.AllowedOrigins {
			if !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// ---- users ----

func (s *Store) CreateUser(_ context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[u.TenantID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range s.users {
		if x.TenantID == u.TenantID && x.Email == u.Email {
			return domain.ErrConflict
		}
	}
	s.users[u.ID] = cloneUser(u)
	return nil
}

func (s *Store) userLocked(tenantID, id string) (*domain.User, error) {
	u, ok := s.users[id]
	if !ok || u.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	return u, nil
}

func (s *Store) GetUser(_ context.Context, tenantID, id string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.userLocked(tenantID, id)
	if err != nil {
		return nil, err
	}
	return cloneUser(u), nil
}

func (s *Store) GetUserByEmail(_ context.Context, tenantID, email string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			return cloneUser(u), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *Store) ListUsers(_ context.Context, tenantID string, f store.UserFilter, p store.Page) ([]*domain.User, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.User
	for _, u := range s.users {
		if u.TenantID != tenantID ||
			(f.Email != "" && !strings.Contains(u.Email, strings.ToLower(f.Email))) ||
			(f.Status != "" && u.Status != f.Status) {
			continue
		}
		all = append(all, cloneUser(u))
	}
	out, total := page(all, p, func(u *domain.User) time.Time { return u.CreatedAt }, func(u *domain.User) string { return u.ID })
	return out, total, nil
}

func (s *Store) UpdateUser(_ context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.userLocked(u.TenantID, u.ID)
	if err != nil {
		return err
	}
	for _, x := range s.users {
		if x.ID != u.ID && x.TenantID == u.TenantID && x.Email == u.Email {
			return domain.ErrConflict
		}
	}
	cur.Email, cur.Name, cur.PasswordHash = u.Email, u.Name, u.PasswordHash
	cur.Status, cur.EmailVerified, cur.UpdatedAt = u.Status, u.EmailVerified, u.UpdatedAt
	return nil
}

func (s *Store) DeleteUser(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.userLocked(tenantID, id); err != nil {
		return err
	}
	delete(s.users, id)
	delete(s.userRoles, id)
	delete(s.legacy, id)
	for sid, sess := range s.sessions {
		if sess.UserID == id {
			s.deleteSessionLocked(sid)
		}
	}
	for h, v := range s.verify {
		if v.UserID == id {
			delete(s.verify, h)
		}
	}
	return nil
}

func (s *Store) IncrementFailedLogins(_ context.Context, tenantID, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.userLocked(tenantID, userID)
	if err != nil {
		return 0, err
	}
	u.FailedLogins++
	return u.FailedLogins, nil
}

func (s *Store) LockUser(_ context.Context, tenantID, userID string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.userLocked(tenantID, userID)
	if err != nil {
		return err
	}
	u.LockedUntil = &until
	return nil
}

func (s *Store) ClearLoginFailures(_ context.Context, tenantID, userID string, lastLogin *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.userLocked(tenantID, userID)
	if err != nil {
		return err
	}
	u.FailedLogins, u.LockedUntil = 0, nil
	if lastLogin != nil {
		u.LastLoginAt = timePtr(lastLogin)
	}
	return nil
}

// ---- permissions & roles ----

func (s *Store) CreatePermission(_ context.Context, p *domain.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[p.TenantID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range s.permissions {
		if x.TenantID == p.TenantID && x.Name == p.Name {
			return domain.ErrConflict
		}
	}
	c := *p
	s.permissions[p.ID] = &c
	return nil
}

func (s *Store) ListPermissions(_ context.Context, tenantID string, p store.Page) ([]*domain.Permission, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.Permission
	for _, x := range s.permissions {
		if x.TenantID == tenantID {
			c := *x
			all = append(all, &c)
		}
	}
	out, total := page(all, p, func(x *domain.Permission) time.Time { return x.CreatedAt }, func(x *domain.Permission) string { return x.ID })
	return out, total, nil
}

func (s *Store) DeletePermission(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.permissions[id]
	if !ok || p.TenantID != tenantID {
		return domain.ErrNotFound
	}
	delete(s.permissions, id)
	for _, r := range s.roles {
		if r.TenantID != tenantID {
			continue
		}
		kept := r.Permissions[:0]
		for _, n := range r.Permissions {
			if n != p.Name {
				kept = append(kept, n)
			}
		}
		r.Permissions = kept
	}
	return nil
}

func (s *Store) CreateRole(_ context.Context, r *domain.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[r.TenantID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range s.roles {
		if x.TenantID == r.TenantID && x.Name == r.Name {
			return domain.ErrConflict
		}
	}
	c := cloneRole(r)
	c.Permissions = []string{}
	s.roles[r.ID] = c
	return nil
}

func (s *Store) roleLocked(tenantID, id string) (*domain.Role, error) {
	r, ok := s.roles[id]
	if !ok || r.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	return r, nil
}

func (s *Store) GetRole(_ context.Context, tenantID, id string) (*domain.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.roleLocked(tenantID, id)
	if err != nil {
		return nil, err
	}
	return cloneRole(r), nil
}

func (s *Store) ListRoles(_ context.Context, tenantID string, p store.Page) ([]*domain.Role, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.Role
	for _, r := range s.roles {
		if r.TenantID == tenantID {
			all = append(all, cloneRole(r))
		}
	}
	out, total := page(all, p, func(r *domain.Role) time.Time { return r.CreatedAt }, func(r *domain.Role) string { return r.ID })
	return out, total, nil
}

func (s *Store) UpdateRole(_ context.Context, r *domain.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.roleLocked(r.TenantID, r.ID)
	if err != nil {
		return err
	}
	for _, x := range s.roles {
		if x.ID != r.ID && x.TenantID == r.TenantID && x.Name == r.Name {
			return domain.ErrConflict
		}
	}
	cur.Name, cur.Description, cur.UpdatedAt = r.Name, r.Description, r.UpdatedAt
	return nil
}

func (s *Store) DeleteRole(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.roleLocked(tenantID, id); err != nil {
		return err
	}
	delete(s.roles, id)
	for _, set := range s.userRoles {
		delete(set, id)
	}
	return nil
}

func (s *Store) SetRolePermissions(_ context.Context, tenantID, roleID string, names []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.roleLocked(tenantID, roleID)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, p := range s.permissions {
		if p.TenantID == tenantID {
			known[p.Name] = true
		}
	}
	set := map[string]bool{}
	for _, n := range names {
		if !known[n] {
			return domain.ErrNotFound
		}
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	r.Permissions = out
	return nil
}

func (s *Store) AssignRole(_ context.Context, tenantID, userID, roleID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.userLocked(tenantID, userID); err != nil {
		return err
	}
	if _, err := s.roleLocked(tenantID, roleID); err != nil {
		return err
	}
	if s.userRoles[userID] == nil {
		s.userRoles[userID] = map[string]bool{}
	}
	s.userRoles[userID][roleID] = true
	return nil
}

func (s *Store) UnassignRole(_ context.Context, tenantID, userID, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.userLocked(tenantID, userID); err != nil {
		return err
	}
	if !s.userRoles[userID][roleID] {
		return domain.ErrNotFound
	}
	delete(s.userRoles[userID], roleID)
	return nil
}

func (s *Store) ListUserRoles(_ context.Context, tenantID, userID string) ([]*domain.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*domain.Role{}
	for id := range s.userRoles[userID] {
		if r, ok := s.roles[id]; ok && r.TenantID == tenantID {
			out = append(out, cloneRole(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---- sessions ----

func (s *Store) deleteSessionLocked(id string) {
	delete(s.sessions, id)
	for h, c := range s.codes {
		if c.SessionID == id {
			delete(s.codes, h)
		}
	}
	for h, t := range s.refresh {
		if t.SessionID == id {
			delete(s.refresh, h)
		}
	}
}

func (s *Store) CreateSession(_ context.Context, x *domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[x.ID] = cloneSession(x)
	return nil
}

func (s *Store) GetSession(_ context.Context, id string) (*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSession(x), nil
}

func (s *Store) ListSessions(_ context.Context, tenantID string, f store.SessionFilter, p store.Page) ([]*domain.Session, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.Session
	for _, x := range s.sessions {
		if x.TenantID != tenantID ||
			(f.UserID != "" && x.UserID != f.UserID) ||
			(f.ActiveOnly && !x.Active(f.Now)) {
			continue
		}
		all = append(all, cloneSession(x))
	}
	out, total := page(all, p, func(x *domain.Session) time.Time { return x.CreatedAt }, func(x *domain.Session) string { return x.ID })
	return out, total, nil
}

func (s *Store) TouchSession(_ context.Context, id string, lastUsed, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok {
		return domain.ErrNotFound
	}
	x.LastUsedAt, x.ExpiresAt = lastUsed, expires
	return nil
}

func (s *Store) RevokeSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok {
		return domain.ErrNotFound
	}
	if x.RevokedAt == nil {
		x.RevokedAt = &at
	}
	return nil
}

func (s *Store) RevokeUserSessions(_ context.Context, tenantID, userID, except string, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, x := range s.sessions {
		if x.TenantID == tenantID && x.UserID == userID && x.ID != except && x.RevokedAt == nil {
			t := at
			x.RevokedAt = &t
			n++
		}
	}
	return n, nil
}

// ---- tokens ----

func (s *Store) CreateRefreshToken(_ context.Context, t *domain.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refresh[t.TokenHash]; ok {
		return domain.ErrConflict
	}
	c := *t
	s.refresh[t.TokenHash] = &c
	return nil
}

func (s *Store) GetRefreshTokenByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[hash]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *t
	c.UsedAt = timePtr(t.UsedAt)
	return &c, nil
}

func (s *Store) ConsumeRefreshToken(_ context.Context, hash string, at time.Time) (*domain.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[hash]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	reused := t.UsedAt != nil
	if !reused {
		t.UsedAt = &at
	}
	c := *t
	c.UsedAt = timePtr(t.UsedAt)
	return &c, reused, nil
}

func (s *Store) CreateVerificationToken(_ context.Context, t *domain.VerificationToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *t
	s.verify[t.TokenHash] = &c
	return nil
}

func (s *Store) ConsumeVerificationToken(_ context.Context, hash, purpose string, at time.Time) (*domain.VerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.verify[hash]
	if !ok || t.Purpose != purpose || t.UsedAt != nil || !at.Before(t.ExpiresAt) {
		return nil, domain.ErrNotFound
	}
	t.UsedAt = &at
	c := *t
	return &c, nil
}

func (s *Store) CreateAuthorizationCode(_ context.Context, c *domain.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.codes[c.CodeHash]; ok {
		return domain.ErrConflict
	}
	cp := *c
	s.codes[c.CodeHash] = &cp
	return nil
}

func (s *Store) ConsumeAuthorizationCode(_ context.Context, hash string, at time.Time) (*domain.AuthorizationCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[hash]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	reused := c.UsedAt != nil
	if !reused {
		c.UsedAt = &at
	}
	cp := *c
	cp.UsedAt = timePtr(c.UsedAt)
	return &cp, reused, nil
}

func cloneLegacy(c *domain.LegacyCredential) *domain.LegacyCredential {
	cp := *c
	cp.Salt, cp.Verifier = append([]byte{}, c.Salt...), append([]byte{}, c.Verifier...)
	return &cp
}

func (s *Store) CreateLegacyCredential(_ context.Context, c *domain.LegacyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.userLocked(c.TenantID, c.UserID); err != nil {
		return err
	}
	for _, x := range s.legacy {
		if x.UserID == c.UserID || (x.TenantID == c.TenantID && x.Username == c.Username) {
			return domain.ErrConflict
		}
	}
	s.legacy[c.UserID] = cloneLegacy(c)
	return nil
}

func (s *Store) GetLegacyCredential(_ context.Context, tenantID, username string) (*domain.LegacyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.legacy {
		if x.TenantID == tenantID && x.Username == username {
			return cloneLegacy(x), nil
		}
	}
	return nil, domain.ErrNotFound
}

// ---- audit & maintenance ----

func (s *Store) AppendAuditEvent(_ context.Context, e *domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *e
	s.audit = append(s.audit, &c)
	return nil
}

func (s *Store) ListAuditEvents(_ context.Context, tenantID string, f store.AuditFilter, p store.Page) ([]*domain.AuditEvent, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []*domain.AuditEvent
	for _, e := range s.audit {
		if e.TenantID != tenantID || (f.Type != "" && e.Type != f.Type) || (f.ActorID != "" && e.ActorID != f.ActorID) {
			continue
		}
		c := *e
		all = append(all, &c)
	}
	out, total := page(all, p, func(e *domain.AuditEvent) time.Time { return e.CreatedAt }, func(e *domain.AuditEvent) string { return e.ID })
	return out, total, nil
}

func (s *Store) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, t := range s.refresh {
		if t.ExpiresAt.Before(before) {
			delete(s.refresh, h)
			n++
		}
	}
	for h, t := range s.verify {
		if t.ExpiresAt.Before(before) {
			delete(s.verify, h)
			n++
		}
	}
	for h, c := range s.codes {
		if c.ExpiresAt.Before(before) {
			delete(s.codes, h)
			n++
		}
	}
	for id, x := range s.sessions {
		if x.ExpiresAt.Before(before) {
			s.deleteSessionLocked(id)
			n++
		}
	}
	return n, nil
}
