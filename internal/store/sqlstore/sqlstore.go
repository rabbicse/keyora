// Package sqlstore implements store.Store on database/sql for PostgreSQL and
// SQLite. It imports no driver: the binary that opens the *sql.DB registers
// one, which keeps third-party code out of the Keyora core module.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/store"
)

const (
	DialectPostgres = "postgres"
	DialectSQLite   = "sqlite"
)

type Store struct {
	db       *sql.DB
	postgres bool
}

var _ store.Store = (*Store)(nil)

// New wraps an open database. dialect is DialectPostgres or DialectSQLite.
func New(db *sql.DB, dialect string) (*Store, error) {
	switch dialect {
	case DialectPostgres, DialectSQLite:
		return &Store{db: db, postgres: dialect == DialectPostgres}, nil
	}
	return nil, fmt.Errorf("sqlstore: unsupported dialect %q", dialect)
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Close() error                   { return s.db.Close() }

// ---- helpers ----

// q rewrites "?" placeholders to "$n" on PostgreSQL. Every value is bound;
// no user input is ever concatenated into SQL text.
func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

func nullMs(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMilli(), Valid: true}
}

func fromNullMs(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMs(v.Int64)
	return &t
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func listFromJSON(v string) []string {
	out := []string{}
	_ = json.Unmarshal([]byte(v), &out)
	return out
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func likeContains(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(v)) + "%"
}

// mapErr translates driver errors into domain errors without importing a driver.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	var st interface{ SQLState() string }
	if errors.As(err, &st) {
		switch st.SQLState() {
		case "23505":
			return domain.ErrConflict
		case "23503":
			return domain.ErrNotFound
		case "22021":
			// e.g. a NUL byte, which PostgreSQL text cannot hold.
			return domain.ErrUnstorable
		}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed"):
		return domain.ErrConflict
	case strings.Contains(msg, "FOREIGN KEY constraint failed"):
		return domain.ErrNotFound
	}
	return err
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q(query), args...)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return n, err
}

// execOne runs a statement that must touch exactly one row.
func (s *Store) execOne(ctx context.Context, query string, args ...any) error {
	n, err := s.exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

// list runs a COUNT plus a newest-first page query sharing one WHERE clause.
func list[T any](ctx context.Context, s *Store, cols, table, where string, args []any, p store.Page, scan func(scanner) (T, error)) ([]T, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM "+table+" WHERE "+where), args...).Scan(&total); err != nil {
		return nil, 0, mapErr(err)
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 1 << 30
	}
	query := "SELECT " + cols + " FROM " + table + " WHERE " + where + " ORDER BY created_at DESC, id ASC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, s.q(query), append(append([]any{}, args...), limit, p.Offset)...)
	if err != nil {
		return nil, 0, mapErr(err)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// ---- tenants ----

const tenantCols = "id, slug, name, status, created_at, updated_at"

func scanTenant(r scanner) (*domain.Tenant, error) {
	var t domain.Tenant
	var c, u int64
	if err := r.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &c, &u); err != nil {
		return nil, mapErr(err)
	}
	t.CreatedAt, t.UpdatedAt = fromMs(c), fromMs(u)
	return &t, nil
}

func (s *Store) CreateTenant(ctx context.Context, t *domain.Tenant) error {
	_, err := s.exec(ctx, "INSERT INTO tenants ("+tenantCols+") VALUES (?,?,?,?,?,?)",
		t.ID, t.Slug, t.Name, t.Status, ms(t.CreatedAt), ms(t.UpdatedAt))
	return err
}

func (s *Store) GetTenant(ctx context.Context, id string) (*domain.Tenant, error) {
	return scanTenant(s.db.QueryRowContext(ctx, s.q("SELECT "+tenantCols+" FROM tenants WHERE id = ?"), id))
}

func (s *Store) ListTenants(ctx context.Context, p store.Page) ([]*domain.Tenant, int, error) {
	return list(ctx, s, tenantCols, "tenants", "1 = 1", nil, p, scanTenant)
}

func (s *Store) UpdateTenant(ctx context.Context, t *domain.Tenant) error {
	return s.execOne(ctx, "UPDATE tenants SET slug = ?, name = ?, status = ?, updated_at = ? WHERE id = ?",
		t.Slug, t.Name, t.Status, ms(t.UpdatedAt), t.ID)
}

// ---- applications ----

const appCols = "id, tenant_id, name, type, client_id, client_secret_hash, redirect_uris, allowed_origins, access_token_ttl, refresh_token_ttl, status, created_at, updated_at"

func scanApp(r scanner) (*domain.Application, error) {
	var a domain.Application
	var redirects, origins string
	var c, u int64
	if err := r.Scan(&a.ID, &a.TenantID, &a.Name, &a.Type, &a.ClientID, &a.ClientSecretHash, &redirects, &origins,
		&a.AccessTokenTTL, &a.RefreshTokenTTL, &a.Status, &c, &u); err != nil {
		return nil, mapErr(err)
	}
	a.RedirectURIs, a.AllowedOrigins = listFromJSON(redirects), listFromJSON(origins)
	a.CreatedAt, a.UpdatedAt = fromMs(c), fromMs(u)
	return &a, nil
}

func (s *Store) CreateApplication(ctx context.Context, a *domain.Application) error {
	_, err := s.exec(ctx, "INSERT INTO applications ("+appCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
		a.ID, a.TenantID, a.Name, a.Type, a.ClientID, a.ClientSecretHash, toJSON(a.RedirectURIs), toJSON(a.AllowedOrigins),
		a.AccessTokenTTL, a.RefreshTokenTTL, a.Status, ms(a.CreatedAt), ms(a.UpdatedAt))
	return err
}

func (s *Store) GetApplication(ctx context.Context, tenantID, id string) (*domain.Application, error) {
	return scanApp(s.db.QueryRowContext(ctx, s.q("SELECT "+appCols+" FROM applications WHERE tenant_id = ? AND id = ?"), tenantID, id))
}

func (s *Store) GetApplicationByClientID(ctx context.Context, clientID string) (*domain.Application, error) {
	return scanApp(s.db.QueryRowContext(ctx, s.q("SELECT "+appCols+" FROM applications WHERE client_id = ?"), clientID))
}

func (s *Store) ListApplications(ctx context.Context, tenantID string, p store.Page) ([]*domain.Application, int, error) {
	return list(ctx, s, appCols, "applications", "tenant_id = ?", []any{tenantID}, p, scanApp)
}

func (s *Store) UpdateApplication(ctx context.Context, a *domain.Application) error {
	return s.execOne(ctx, `UPDATE applications SET name = ?, type = ?, client_secret_hash = ?, redirect_uris = ?, allowed_origins = ?,
		access_token_ttl = ?, refresh_token_ttl = ?, status = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		a.Name, a.Type, a.ClientSecretHash, toJSON(a.RedirectURIs), toJSON(a.AllowedOrigins),
		a.AccessTokenTTL, a.RefreshTokenTTL, a.Status, ms(a.UpdatedAt), a.TenantID, a.ID)
}

func (s *Store) DeleteApplication(ctx context.Context, tenantID, id string) error {
	return s.execOne(ctx, "DELETE FROM applications WHERE tenant_id = ? AND id = ?", tenantID, id)
}

func (s *Store) ListAllowedOrigins(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q("SELECT allowed_origins FROM applications WHERE status = ?"), domain.StatusActive)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		for _, o := range listFromJSON(raw) {
			if !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	return out, rows.Err()
}

// ---- users ----

const userCols = "id, tenant_id, email, name, password_hash, status, email_verified, failed_logins, locked_until, last_login_at, created_at, updated_at"

func scanUser(r scanner) (*domain.User, error) {
	var u domain.User
	var locked, last sql.NullInt64
	var c, up int64
	if err := r.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.PasswordHash, &u.Status, &u.EmailVerified,
		&u.FailedLogins, &locked, &last, &c, &up); err != nil {
		return nil, mapErr(err)
	}
	u.LockedUntil, u.LastLoginAt = fromNullMs(locked), fromNullMs(last)
	u.CreatedAt, u.UpdatedAt = fromMs(c), fromMs(up)
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	_, err := s.exec(ctx, "INSERT INTO users ("+userCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
		u.ID, u.TenantID, u.Email, u.Name, u.PasswordHash, u.Status, u.EmailVerified, u.FailedLogins,
		nullMs(u.LockedUntil), nullMs(u.LastLoginAt), ms(u.CreatedAt), ms(u.UpdatedAt))
	return err
}

func (s *Store) GetUser(ctx context.Context, tenantID, id string) (*domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q("SELECT "+userCols+" FROM users WHERE tenant_id = ? AND id = ?"), tenantID, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, tenantID, email string) (*domain.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q("SELECT "+userCols+" FROM users WHERE tenant_id = ? AND email = ?"), tenantID, email))
}

func (s *Store) ListUsers(ctx context.Context, tenantID string, f store.UserFilter, p store.Page) ([]*domain.User, int, error) {
	where, args := "tenant_id = ?", []any{tenantID}
	if f.Email != "" {
		where += ` AND email LIKE ? ESCAPE '\'`
		args = append(args, likeContains(f.Email))
	}
	if f.Status != "" {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	return list(ctx, s, userCols, "users", where, args, p, scanUser)
}

func (s *Store) UpdateUser(ctx context.Context, u *domain.User) error {
	return s.execOne(ctx, `UPDATE users SET email = ?, name = ?, password_hash = ?, status = ?, email_verified = ?, updated_at = ?
		WHERE tenant_id = ? AND id = ?`,
		u.Email, u.Name, u.PasswordHash, u.Status, u.EmailVerified, ms(u.UpdatedAt), u.TenantID, u.ID)
}

func (s *Store) DeleteUser(ctx context.Context, tenantID, id string) error {
	return s.execOne(ctx, "DELETE FROM users WHERE tenant_id = ? AND id = ?", tenantID, id)
}

func (s *Store) IncrementFailedLogins(ctx context.Context, tenantID, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		s.q("UPDATE users SET failed_logins = failed_logins + 1 WHERE tenant_id = ? AND id = ? RETURNING failed_logins"),
		tenantID, userID).Scan(&n)
	return n, mapErr(err)
}

func (s *Store) LockUser(ctx context.Context, tenantID, userID string, until time.Time) error {
	return s.execOne(ctx, "UPDATE users SET locked_until = ? WHERE tenant_id = ? AND id = ?", ms(until), tenantID, userID)
}

func (s *Store) ClearLoginFailures(ctx context.Context, tenantID, userID string, lastLogin *time.Time) error {
	if lastLogin == nil {
		return s.execOne(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE tenant_id = ? AND id = ?", tenantID, userID)
	}
	return s.execOne(ctx, "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE tenant_id = ? AND id = ?",
		ms(*lastLogin), tenantID, userID)
}

// ---- permissions & roles ----

const permCols = "id, tenant_id, name, description, created_at"

func scanPerm(r scanner) (*domain.Permission, error) {
	var p domain.Permission
	var c int64
	if err := r.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &c); err != nil {
		return nil, mapErr(err)
	}
	p.CreatedAt = fromMs(c)
	return &p, nil
}

func (s *Store) CreatePermission(ctx context.Context, p *domain.Permission) error {
	_, err := s.exec(ctx, "INSERT INTO permissions ("+permCols+") VALUES (?,?,?,?,?)",
		p.ID, p.TenantID, p.Name, p.Description, ms(p.CreatedAt))
	return err
}

func (s *Store) ListPermissions(ctx context.Context, tenantID string, p store.Page) ([]*domain.Permission, int, error) {
	return list(ctx, s, permCols, "permissions", "tenant_id = ?", []any{tenantID}, p, scanPerm)
}

func (s *Store) DeletePermission(ctx context.Context, tenantID, id string) error {
	return s.execOne(ctx, "DELETE FROM permissions WHERE tenant_id = ? AND id = ?", tenantID, id)
}

const roleCols = "id, tenant_id, name, description, created_at, updated_at"

func scanRole(r scanner) (*domain.Role, error) {
	var x domain.Role
	var c, u int64
	if err := r.Scan(&x.ID, &x.TenantID, &x.Name, &x.Description, &c, &u); err != nil {
		return nil, mapErr(err)
	}
	x.Permissions = []string{}
	x.CreatedAt, x.UpdatedAt = fromMs(c), fromMs(u)
	return &x, nil
}

// loadPermissions fills Role.Permissions for a batch of roles in one query.
func (s *Store) loadPermissions(ctx context.Context, roles []*domain.Role) error {
	if len(roles) == 0 {
		return nil
	}
	byID := make(map[string]*domain.Role, len(roles))
	args := make([]any, 0, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
		args = append(args, r.ID)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT rp.role_id, p.name FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id IN (`+placeholders(len(roles))+`) ORDER BY p.name`), args...)
	if err != nil {
		return mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var roleID, name string
		if err := rows.Scan(&roleID, &name); err != nil {
			return err
		}
		byID[roleID].Permissions = append(byID[roleID].Permissions, name)
	}
	return rows.Err()
}

func (s *Store) CreateRole(ctx context.Context, r *domain.Role) error {
	_, err := s.exec(ctx, "INSERT INTO roles ("+roleCols+") VALUES (?,?,?,?,?,?)",
		r.ID, r.TenantID, r.Name, r.Description, ms(r.CreatedAt), ms(r.UpdatedAt))
	return err
}

func (s *Store) GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx, s.q("SELECT "+roleCols+" FROM roles WHERE tenant_id = ? AND id = ?"), tenantID, id))
	if err != nil {
		return nil, err
	}
	return r, s.loadPermissions(ctx, []*domain.Role{r})
}

func (s *Store) ListRoles(ctx context.Context, tenantID string, p store.Page) ([]*domain.Role, int, error) {
	roles, total, err := list(ctx, s, roleCols, "roles", "tenant_id = ?", []any{tenantID}, p, scanRole)
	if err != nil {
		return nil, 0, err
	}
	return roles, total, s.loadPermissions(ctx, roles)
}

func (s *Store) UpdateRole(ctx context.Context, r *domain.Role) error {
	return s.execOne(ctx, "UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
		r.Name, r.Description, ms(r.UpdatedAt), r.TenantID, r.ID)
}

func (s *Store) DeleteRole(ctx context.Context, tenantID, id string) error {
	return s.execOne(ctx, "DELETE FROM roles WHERE tenant_id = ? AND id = ?", tenantID, id)
}

func (s *Store) SetRolePermissions(ctx context.Context, tenantID, roleID string, names []string) error {
	uniq := map[string]bool{}
	for _, n := range names {
		uniq[n] = true
	}
	names = names[:0:0]
	for n := range uniq {
		names = append(names, n)
	}
	sort.Strings(names)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var found string
	if err := tx.QueryRowContext(ctx, s.q("SELECT id FROM roles WHERE tenant_id = ? AND id = ?"), tenantID, roleID).Scan(&found); err != nil {
		return mapErr(err)
	}
	var ids []string
	if len(names) > 0 {
		args := []any{tenantID}
		for _, n := range names {
			args = append(args, n)
		}
		rows, err := tx.QueryContext(ctx, s.q("SELECT id FROM permissions WHERE tenant_id = ? AND name IN ("+placeholders(len(names))+")"), args...)
		if err != nil {
			return mapErr(err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) != len(names) {
			return domain.ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, s.q("DELETE FROM role_permissions WHERE role_id = ?"), roleID); err != nil {
		return mapErr(err)
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, s.q("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)"), roleID, id); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit()
}

func (s *Store) AssignRole(ctx context.Context, tenantID, userID, roleID string, at time.Time) error {
	// Both sides must belong to the tenant; this is what stops a role from
	// one tenant being attached to a user of another.
	var n int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT
		(SELECT COUNT(*) FROM users WHERE tenant_id = ? AND id = ?) +
		(SELECT COUNT(*) FROM roles WHERE tenant_id = ? AND id = ?)`), tenantID, userID, tenantID, roleID).Scan(&n); err != nil {
		return mapErr(err)
	}
	if n != 2 {
		return domain.ErrNotFound
	}
	_, err := s.exec(ctx, "INSERT INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)", userID, roleID, ms(at))
	if errors.Is(err, domain.ErrConflict) {
		return nil // already assigned
	}
	return err
}

func (s *Store) UnassignRole(ctx context.Context, tenantID, userID, roleID string) error {
	return s.execOne(ctx, `DELETE FROM user_roles WHERE user_id = ? AND role_id = ?
		AND user_id IN (SELECT id FROM users WHERE tenant_id = ?)`, userID, roleID, tenantID)
}

func (s *Store) ListUserRoles(ctx context.Context, tenantID, userID string) ([]*domain.Role, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT r.id, r.tenant_id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r JOIN user_roles ur ON ur.role_id = r.id
		WHERE r.tenant_id = ? AND ur.user_id = ? ORDER BY r.name`), tenantID, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	roles := []*domain.Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return roles, s.loadPermissions(ctx, roles)
}

// ---- sessions ----

const sessionCols = "id, tenant_id, user_id, application_id, ip, user_agent, created_at, last_used_at, expires_at, revoked_at"

func scanSession(r scanner) (*domain.Session, error) {
	var x domain.Session
	var c, l, e int64
	var rev sql.NullInt64
	if err := r.Scan(&x.ID, &x.TenantID, &x.UserID, &x.ApplicationID, &x.IP, &x.UserAgent, &c, &l, &e, &rev); err != nil {
		return nil, mapErr(err)
	}
	x.CreatedAt, x.LastUsedAt, x.ExpiresAt, x.RevokedAt = fromMs(c), fromMs(l), fromMs(e), fromNullMs(rev)
	return &x, nil
}

func (s *Store) CreateSession(ctx context.Context, x *domain.Session) error {
	_, err := s.exec(ctx, "INSERT INTO sessions ("+sessionCols+") VALUES (?,?,?,?,?,?,?,?,?,?)",
		x.ID, x.TenantID, x.UserID, x.ApplicationID, x.IP, x.UserAgent, ms(x.CreatedAt), ms(x.LastUsedAt), ms(x.ExpiresAt), nullMs(x.RevokedAt))
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (*domain.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, s.q("SELECT "+sessionCols+" FROM sessions WHERE id = ?"), id))
}

func (s *Store) ListSessions(ctx context.Context, tenantID string, f store.SessionFilter, p store.Page) ([]*domain.Session, int, error) {
	where, args := "tenant_id = ?", []any{tenantID}
	if f.UserID != "" {
		where += " AND user_id = ?"
		args = append(args, f.UserID)
	}
	if f.ActiveOnly {
		where += " AND revoked_at IS NULL AND expires_at > ?"
		args = append(args, ms(f.Now))
	}
	return list(ctx, s, sessionCols, "sessions", where, args, p, scanSession)
}

func (s *Store) TouchSession(ctx context.Context, id string, lastUsed, expires time.Time) error {
	return s.execOne(ctx, "UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE id = ?", ms(lastUsed), ms(expires), id)
}

func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) error {
	return s.execOne(ctx, "UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", ms(at), id)
}

func (s *Store) RevokeUserSessions(ctx context.Context, tenantID, userID, except string, at time.Time) (int, error) {
	n, err := s.exec(ctx, "UPDATE sessions SET revoked_at = ? WHERE tenant_id = ? AND user_id = ? AND id <> ? AND revoked_at IS NULL",
		ms(at), tenantID, userID, except)
	return int(n), err
}

// ---- tokens ----

const refreshCols = "id, session_id, token_hash, created_at, expires_at, used_at"

func scanRefresh(r scanner) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	var c, e int64
	var used sql.NullInt64
	if err := r.Scan(&t.ID, &t.SessionID, &t.TokenHash, &c, &e, &used); err != nil {
		return nil, mapErr(err)
	}
	t.CreatedAt, t.ExpiresAt, t.UsedAt = fromMs(c), fromMs(e), fromNullMs(used)
	return &t, nil
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	_, err := s.exec(ctx, "INSERT INTO refresh_tokens ("+refreshCols+") VALUES (?,?,?,?,?,?)",
		t.ID, t.SessionID, t.TokenHash, ms(t.CreatedAt), ms(t.ExpiresAt), nullMs(t.UsedAt))
	return err
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	return scanRefresh(s.db.QueryRowContext(ctx, s.q("SELECT "+refreshCols+" FROM refresh_tokens WHERE token_hash = ?"), hash))
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, hash string, at time.Time) (*domain.RefreshToken, bool, error) {
	// The conditional UPDATE is the atomic step: of any number of concurrent
	// callers presenting the same token, exactly one sees a row change.
	n, err := s.exec(ctx, "UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL", ms(at), hash)
	if err != nil {
		return nil, false, err
	}
	t, err := s.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil, false, err
	}
	return t, n == 0, nil
}

func (s *Store) CreateVerificationToken(ctx context.Context, t *domain.VerificationToken) error {
	_, err := s.exec(ctx, `INSERT INTO verification_tokens (id, tenant_id, user_id, purpose, token_hash, created_at, expires_at, used_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		t.ID, t.TenantID, t.UserID, t.Purpose, t.TokenHash, ms(t.CreatedAt), ms(t.ExpiresAt), nullMs(t.UsedAt))
	return err
}

func (s *Store) ConsumeVerificationToken(ctx context.Context, hash, purpose string, at time.Time) (*domain.VerificationToken, error) {
	if err := s.execOne(ctx, `UPDATE verification_tokens SET used_at = ?
		WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?`, ms(at), hash, purpose, ms(at)); err != nil {
		return nil, err
	}
	var t domain.VerificationToken
	var c, e int64
	var used sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, tenant_id, user_id, purpose, token_hash, created_at, expires_at, used_at
		FROM verification_tokens WHERE token_hash = ?`), hash).
		Scan(&t.ID, &t.TenantID, &t.UserID, &t.Purpose, &t.TokenHash, &c, &e, &used)
	if err != nil {
		return nil, mapErr(err)
	}
	t.CreatedAt, t.ExpiresAt, t.UsedAt = fromMs(c), fromMs(e), fromNullMs(used)
	return &t, nil
}

const codeCols = "id, code_hash, tenant_id, application_id, user_id, session_id, redirect_uri, code_challenge, scope, nonce, created_at, expires_at, used_at"

func (s *Store) CreateAuthorizationCode(ctx context.Context, c *domain.AuthorizationCode) error {
	_, err := s.exec(ctx, "INSERT INTO authorization_codes ("+codeCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
		c.ID, c.CodeHash, c.TenantID, c.ApplicationID, c.UserID, c.SessionID, c.RedirectURI, c.CodeChallenge, c.Scope, c.Nonce,
		ms(c.CreatedAt), ms(c.ExpiresAt), nullMs(c.UsedAt))
	return err
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, hash string, at time.Time) (*domain.AuthorizationCode, bool, error) {
	// As with refresh tokens, the conditional UPDATE picks exactly one winner.
	n, err := s.exec(ctx, "UPDATE authorization_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL", ms(at), hash)
	if err != nil {
		return nil, false, err
	}
	var c domain.AuthorizationCode
	var created, expires int64
	var used sql.NullInt64
	err = s.db.QueryRowContext(ctx, s.q("SELECT "+codeCols+" FROM authorization_codes WHERE code_hash = ?"), hash).
		Scan(&c.ID, &c.CodeHash, &c.TenantID, &c.ApplicationID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.CodeChallenge, &c.Scope, &c.Nonce,
			&created, &expires, &used)
	if err != nil {
		return nil, false, mapErr(err)
	}
	c.CreatedAt, c.ExpiresAt, c.UsedAt = fromMs(created), fromMs(expires), fromNullMs(used)
	return &c, n == 0, nil
}

func (s *Store) CreateLegacyCredential(ctx context.Context, c *domain.LegacyCredential) error {
	// The sub-select makes the insert a no-op unless the user is in the tenant.
	n, err := s.exec(ctx, `INSERT INTO legacy_credentials (user_id, tenant_id, username, salt, verifier, created_at)
		SELECT id, tenant_id, ?, ?, ?, ? FROM users WHERE tenant_id = ? AND id = ?`,
		c.Username, base64.RawURLEncoding.EncodeToString(c.Salt), base64.RawURLEncoding.EncodeToString(c.Verifier),
		ms(c.CreatedAt), c.TenantID, c.UserID)
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) GetLegacyCredential(ctx context.Context, tenantID, username string) (*domain.LegacyCredential, error) {
	var c domain.LegacyCredential
	var salt, verifier string
	var created int64
	err := s.db.QueryRowContext(ctx, s.q(`SELECT user_id, tenant_id, username, salt, verifier, created_at
		FROM legacy_credentials WHERE tenant_id = ? AND username = ?`), tenantID, username).
		Scan(&c.UserID, &c.TenantID, &c.Username, &salt, &verifier, &created)
	if err != nil {
		return nil, mapErr(err)
	}
	c.Salt, _ = base64.RawURLEncoding.DecodeString(salt)
	c.Verifier, _ = base64.RawURLEncoding.DecodeString(verifier)
	c.CreatedAt = fromMs(created)
	return &c, nil
}

// ---- audit & maintenance ----

const auditCols = "id, tenant_id, type, actor_type, actor_id, target_id, ip, user_agent, request_id, metadata, created_at"

func scanAudit(r scanner) (*domain.AuditEvent, error) {
	var e domain.AuditEvent
	var meta string
	var c int64
	if err := r.Scan(&e.ID, &e.TenantID, &e.Type, &e.ActorType, &e.ActorID, &e.TargetID, &e.IP, &e.UserAgent, &e.RequestID, &meta, &c); err != nil {
		return nil, mapErr(err)
	}
	if meta != "" && meta != "null" {
		_ = json.Unmarshal([]byte(meta), &e.Metadata)
	}
	e.CreatedAt = fromMs(c)
	return &e, nil
}

func (s *Store) AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error {
	_, err := s.exec(ctx, "INSERT INTO audit_events ("+auditCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?)",
		e.ID, e.TenantID, e.Type, e.ActorType, e.ActorID, e.TargetID, e.IP, e.UserAgent, e.RequestID, toJSON(e.Metadata), ms(e.CreatedAt))
	return err
}

func (s *Store) ListAuditEvents(ctx context.Context, tenantID string, f store.AuditFilter, p store.Page) ([]*domain.AuditEvent, int, error) {
	where, args := "tenant_id = ?", []any{tenantID}
	if f.Type != "" {
		where += " AND type = ?"
		args = append(args, f.Type)
	}
	if f.ActorID != "" {
		where += " AND actor_id = ?"
		args = append(args, f.ActorID)
	}
	return list(ctx, s, auditCols, "audit_events", where, args, p, scanAudit)
}

func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	total := int64(0)
	for _, table := range []string{"refresh_tokens", "verification_tokens", "authorization_codes", "sessions"} {
		n, err := s.exec(ctx, "DELETE FROM "+table+" WHERE expires_at < ?", ms(before))
		if err != nil {
			return int(total), err
		}
		total += n
	}
	return int(total), nil
}
