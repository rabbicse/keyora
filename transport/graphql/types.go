package graphqlapi

import (
	"errors"
	"math"
	"time"

	graphql "github.com/graph-gophers/graphql-go"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

// The structs in this file are what the schema's object types resolve from,
// field by field. Each is filled from a domain value by an explicit
// conversion, so a stored secret (a password hash, a client secret hash) has
// no way into a response: there is no field to carry it.

type tenant struct {
	ID                   graphql.ID
	Slug, Name, Status   string
	CreatedAt, UpdatedAt graphql.Time
}

func newTenant(t *domain.Tenant) *tenant {
	return &tenant{ID: graphql.ID(t.ID), Slug: t.Slug, Name: t.Name, Status: t.Status,
		CreatedAt: ts(t.CreatedAt), UpdatedAt: ts(t.UpdatedAt)}
}

type application struct {
	ID, TenantID           graphql.ID
	Name, Type, ClientID   string
	RedirectURIs           []string
	AllowedOrigins         []string
	AccessTokenTTLSeconds  int32
	RefreshTokenTTLSeconds int32
	Status                 string
	CreatedAt, UpdatedAt   graphql.Time
}

func newApplication(a *domain.Application) *application {
	return &application{ID: graphql.ID(a.ID), TenantID: graphql.ID(a.TenantID), Name: a.Name, Type: a.Type, ClientID: a.ClientID,
		RedirectURIs: a.RedirectURIs, AllowedOrigins: a.AllowedOrigins,
		AccessTokenTTLSeconds: i32(a.AccessTokenTTL), RefreshTokenTTLSeconds: i32(a.RefreshTokenTTL),
		Status: a.Status, CreatedAt: ts(a.CreatedAt), UpdatedAt: ts(a.UpdatedAt)}
}

// applicationWithSecret is returned only by createApplication and
// rotateApplicationSecret, the two operations that generate a secret.
type applicationWithSecret struct {
	Application  *application
	ClientSecret *string
}

type user struct {
	ID, TenantID             graphql.ID
	Email, Name, Status      string
	EmailVerified            bool
	LockedUntil, LastLoginAt *graphql.Time
	CreatedAt, UpdatedAt     graphql.Time
}

func newUser(u *domain.User) *user {
	return &user{ID: graphql.ID(u.ID), TenantID: graphql.ID(u.TenantID), Email: u.Email, Name: u.Name, Status: u.Status,
		EmailVerified: u.EmailVerified, LockedUntil: optionalTime(u.LockedUntil), LastLoginAt: optionalTime(u.LastLoginAt),
		CreatedAt: ts(u.CreatedAt), UpdatedAt: ts(u.UpdatedAt)}
}

type profile struct {
	User               *user
	Roles, Permissions []string
}

type permission struct {
	ID, TenantID      graphql.ID
	Name, Description string
	CreatedAt         graphql.Time
}

func newPermission(p *domain.Permission) *permission {
	return &permission{ID: graphql.ID(p.ID), TenantID: graphql.ID(p.TenantID), Name: p.Name, Description: p.Description,
		CreatedAt: ts(p.CreatedAt)}
}

type role struct {
	ID, TenantID         graphql.ID
	Name, Description    string
	Permissions          []string
	CreatedAt, UpdatedAt graphql.Time
}

func newRole(r *domain.Role) *role {
	return &role{ID: graphql.ID(r.ID), TenantID: graphql.ID(r.TenantID), Name: r.Name, Description: r.Description,
		Permissions: r.Permissions, CreatedAt: ts(r.CreatedAt), UpdatedAt: ts(r.UpdatedAt)}
}

type session struct {
	ID, TenantID, UserID, ApplicationID graphql.ID
	IP, UserAgent                       string
	CreatedAt, LastUsedAt, ExpiresAt    graphql.Time
	RevokedAt                           *graphql.Time
}

func newSession(s *domain.Session) *session {
	return &session{ID: graphql.ID(s.ID), TenantID: graphql.ID(s.TenantID), UserID: graphql.ID(s.UserID),
		ApplicationID: graphql.ID(s.ApplicationID), IP: s.IP, UserAgent: s.UserAgent,
		CreatedAt: ts(s.CreatedAt), LastUsedAt: ts(s.LastUsedAt), ExpiresAt: ts(s.ExpiresAt), RevokedAt: optionalTime(s.RevokedAt)}
}

type auditEvent struct {
	ID, TenantID                       graphql.ID
	Type, ActorType, ActorID           string
	TargetID, IP, UserAgent, RequestID *string
	Metadata                           stringMap
	CreatedAt                          graphql.Time
}

func newAuditEvent(e *domain.AuditEvent) *auditEvent {
	md := stringMap{}
	for k, v := range e.Metadata {
		md[k] = v
	}
	return &auditEvent{ID: graphql.ID(e.ID), TenantID: graphql.ID(e.TenantID), Type: e.Type, ActorType: e.ActorType, ActorID: e.ActorID,
		TargetID: optional(e.TargetID), IP: optional(e.IP), UserAgent: optional(e.UserAgent), RequestID: optional(e.RequestID),
		Metadata: md, CreatedAt: ts(e.CreatedAt)}
}

type tokens struct {
	AccessToken, TokenType string
	ExpiresIn              int32
	RefreshToken           *string
	RefreshExpiresIn       *int32
	SessionID              *graphql.ID
	IDToken, Scope         *string
}

func newTokens(t *service.Tokens, scope string) *tokens {
	out := &tokens{AccessToken: t.AccessToken, TokenType: t.TokenType, ExpiresIn: i32(t.ExpiresIn),
		RefreshToken: optional(t.RefreshToken), SessionID: optional(graphql.ID(t.SessionID)),
		IDToken: optional(t.IDToken), Scope: optional(scope)}
	if t.RefreshExpiresIn != 0 {
		n := i32(t.RefreshExpiresIn)
		out.RefreshExpiresIn = &n
	}
	return out
}

type loginResult struct {
	Tokens *tokens
	User   *user
}

type tokenIntrospection struct {
	Active              bool
	Subject, TenantID   *graphql.ID
	ClientID            *string
	SessionID           *graphql.ID
	Email               *string
	Roles, Permissions  []string
	Issuer              *string
	ExpiresAt, IssuedAt *graphql.Time
}

func newTokenIntrospection(in *service.Introspection) *tokenIntrospection {
	return &tokenIntrospection{Active: in.Active, Subject: optional(graphql.ID(in.Subject)), TenantID: optional(graphql.ID(in.TenantID)),
		ClientID: optional(in.ClientID), SessionID: optional(graphql.ID(in.SessionID)), Email: optional(in.Email),
		Roles: in.Roles, Permissions: in.Permissions, Issuer: optional(in.Issuer),
		ExpiresAt: unixTime(in.ExpiresAt), IssuedAt: unixTime(in.IssuedAt)}
}

type userInfo struct {
	Sub           graphql.ID
	Email         *string
	EmailVerified *bool
	Name          *string
}

type authorization struct {
	Code        string
	State       *string
	RedirectURI string
	RedirectTo  string
	ExpiresIn   int32
	Iss         string
}

// connection is one page of a list.
type connection[T any] struct {
	Items                []*T
	Total, Limit, Offset int32
}

func newConnection[D, T any](items []*D, convert func(*D) *T, total int, p store.Page) *connection[T] {
	return &connection[T]{Items: convertAll(items, convert), Total: i32(int64(total)), Limit: i32(int64(p.Limit)), Offset: i32(int64(p.Offset))}
}

func convertAll[D, T any](items []*D, convert func(*D) *T) []*T {
	out := make([]*T, len(items))
	for i, it := range items {
		out[i] = convert(it)
	}
	return out
}

// stringMap is the StringMap scalar. It is only ever sent, never received.
type stringMap map[string]string

func (stringMap) ImplementsGraphQLType(name string) bool { return name == "StringMap" }

func (*stringMap) UnmarshalGraphQL(any) error {
	return errors.New("StringMap cannot be used as input")
}

// ---- small conversions ----

func ts(t time.Time) graphql.Time { return graphql.Time{Time: t} }

func optionalTime(t *time.Time) *graphql.Time {
	if t == nil {
		return nil
	}
	return &graphql.Time{Time: *t}
}

// unixTime converts a JWT timestamp; zero means the claim is absent.
func unixTime(sec int64) *graphql.Time {
	if sec == 0 {
		return nil
	}
	return &graphql.Time{Time: time.Unix(sec, 0).UTC()}
}

// optional maps the zero value, which the service uses for "absent", to null.
func optional[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}

// i32 converts to GraphQL's 32-bit Int, saturating instead of wrapping.
func i32(n int64) int32 {
	return int32(min(max(n, math.MinInt32), math.MaxInt32))
}

func deref[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return v
}
