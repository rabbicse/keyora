package graphqlapi

import (
	"context"

	graphql "github.com/graph-gophers/graphql-go"

	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

// Management: the fields REST serves under /api/v1/tenants. Every field
// that names a tenant goes through resolver.tenantAdmin, which is the
// cross-tenant boundary; the service is only ever given the tenant ID that
// check approved.

// ---- tenants (root only, except reading your own) ----

func (r *resolver) CreateTenant(ctx context.Context, args struct{ Slug, Name string }) (*tenant, error) {
	m, err := r.root(ctx)
	if err != nil {
		return nil, err
	}
	t, err := r.svc.CreateTenant(ctx, service.TenantInput{Slug: &args.Slug, Name: &args.Name}, m)
	if err != nil {
		return nil, err
	}
	return newTenant(t), nil
}

func (r *resolver) Tenants(ctx context.Context, args pageArgs) (*connection[tenant], error) {
	if _, err := r.root(ctx); err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListTenants(ctx, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newTenant, total, pg), nil
}

func (r *resolver) Tenant(ctx context.Context, args struct{ ID graphql.ID }) (*tenant, error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.ID)
	if err != nil {
		return nil, err
	}
	t, err := r.svc.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return newTenant(t), nil
}

func (r *resolver) UpdateTenant(ctx context.Context, args struct {
	ID           graphql.ID
	Name, Status *string
}) (*tenant, error) {
	m, err := r.root(ctx)
	if err != nil {
		return nil, err
	}
	t, err := r.svc.UpdateTenant(ctx, string(args.ID), service.TenantInput{Name: args.Name, Status: args.Status}, m)
	if err != nil {
		return nil, err
	}
	return newTenant(t), nil
}

// ---- applications ----

type applicationInput struct {
	Name, Type             *string
	RedirectURIs           *[]string
	AllowedOrigins         *[]string
	AccessTokenTTLSeconds  *int32
	RefreshTokenTTLSeconds *int32
	Status                 *string
}

func (in applicationInput) input() service.ApplicationInput {
	return service.ApplicationInput{Name: in.Name, Type: in.Type, RedirectURIs: in.RedirectURIs,
		AllowedOrigins: in.AllowedOrigins, AccessTokenTTL: widen(in.AccessTokenTTLSeconds),
		RefreshTokenTTL: widen(in.RefreshTokenTTLSeconds), Status: in.Status}
}

func widen(n *int32) *int64 {
	if n == nil {
		return nil
	}
	v := int64(*n)
	return &v
}

func (r *resolver) CreateApplication(ctx context.Context, args struct {
	TenantID graphql.ID
	Input    applicationInput
}) (*applicationWithSecret, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	app, secret, err := r.svc.CreateApplication(ctx, tenantID, args.Input.input(), m)
	if err != nil {
		return nil, err
	}
	return &applicationWithSecret{Application: newApplication(app), ClientSecret: optional(secret)}, nil
}

func (r *resolver) Applications(ctx context.Context, args struct {
	TenantID graphql.ID
	pageArgs
}) (*connection[application], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListApplications(ctx, tenantID, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newApplication, total, pg), nil
}

func (r *resolver) Application(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*application, error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	app, err := r.svc.GetApplication(ctx, tenantID, string(args.ID))
	if err != nil {
		return nil, err
	}
	return newApplication(app), nil
}

func (r *resolver) UpdateApplication(ctx context.Context, args struct {
	TenantID, ID graphql.ID
	Input        applicationInput
}) (*application, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	app, err := r.svc.UpdateApplication(ctx, tenantID, string(args.ID), args.Input.input(), m)
	if err != nil {
		return nil, err
	}
	return newApplication(app), nil
}

func (r *resolver) DeleteApplication(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.DeleteApplication(ctx, tenantID, string(args.ID), m))
}

func (r *resolver) RotateApplicationSecret(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*applicationWithSecret, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	app, secret, err := r.svc.RotateApplicationSecret(ctx, tenantID, string(args.ID), m)
	if err != nil {
		return nil, err
	}
	return &applicationWithSecret{Application: newApplication(app), ClientSecret: optional(secret)}, nil
}

// ---- users ----

func (r *resolver) CreateUser(ctx context.Context, args struct {
	TenantID        graphql.ID
	Email, Password string
	Name            *string
	EmailVerified   *bool
}) (*user, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.AdminCreateUser(ctx, tenantID,
		service.UserInput{Email: &args.Email, Password: &args.Password, Name: args.Name, EmailVerified: args.EmailVerified}, m)
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) Users(ctx context.Context, args struct {
	TenantID      graphql.ID
	Email, Status *string
	pageArgs
}) (*connection[user], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListUsers(ctx, tenantID, store.UserFilter{Email: deref(args.Email), Status: deref(args.Status)}, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newUser, total, pg), nil
}

func (r *resolver) User(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*user, error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.GetUser(ctx, tenantID, string(args.ID))
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) UpdateUser(ctx context.Context, args struct {
	TenantID, ID  graphql.ID
	Name, Status  *string
	EmailVerified *bool
}) (*user, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.UpdateUser(ctx, tenantID, string(args.ID),
		service.UserInput{Name: args.Name, Status: args.Status, EmailVerified: args.EmailVerified}, m)
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) DeleteUser(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.DeleteUser(ctx, tenantID, string(args.ID), m))
}

func (r *resolver) UnlockUser(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*user, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.UnlockUser(ctx, tenantID, string(args.ID), m)
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) UserRoles(ctx context.Context, args struct{ TenantID, UserID graphql.ID }) (*[]*role, error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	roles, err := r.svc.ListUserRoles(ctx, tenantID, string(args.UserID))
	if err != nil {
		return nil, err
	}
	out := convertAll(roles, newRole)
	return &out, nil
}

func (r *resolver) AssignRole(ctx context.Context, args struct{ TenantID, UserID, RoleID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.AssignRole(ctx, tenantID, string(args.UserID), string(args.RoleID), m))
}

func (r *resolver) UnassignRole(ctx context.Context, args struct{ TenantID, UserID, RoleID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.UnassignRole(ctx, tenantID, string(args.UserID), string(args.RoleID), m))
}

// ---- permissions & roles ----

func (r *resolver) CreatePermission(ctx context.Context, args struct {
	TenantID    graphql.ID
	Name        string
	Description *string
}) (*permission, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	p, err := r.svc.CreatePermission(ctx, tenantID, args.Name, deref(args.Description), m)
	if err != nil {
		return nil, err
	}
	return newPermission(p), nil
}

func (r *resolver) Permissions(ctx context.Context, args struct {
	TenantID graphql.ID
	pageArgs
}) (*connection[permission], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListPermissions(ctx, tenantID, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newPermission, total, pg), nil
}

func (r *resolver) DeletePermission(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.DeletePermission(ctx, tenantID, string(args.ID), m))
}

func (r *resolver) CreateRole(ctx context.Context, args struct {
	TenantID    graphql.ID
	Name        string
	Description *string
	Permissions *[]string
}) (*role, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	v, err := r.svc.CreateRole(ctx, tenantID, args.Name, deref(args.Description), deref(args.Permissions), m)
	if err != nil {
		return nil, err
	}
	return newRole(v), nil
}

func (r *resolver) Roles(ctx context.Context, args struct {
	TenantID graphql.ID
	pageArgs
}) (*connection[role], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListRoles(ctx, tenantID, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newRole, total, pg), nil
}

func (r *resolver) Role(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*role, error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	v, err := r.svc.GetRole(ctx, tenantID, string(args.ID))
	if err != nil {
		return nil, err
	}
	return newRole(v), nil
}

func (r *resolver) UpdateRole(ctx context.Context, args struct {
	TenantID, ID      graphql.ID
	Name, Description *string
}) (*role, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	v, err := r.svc.UpdateRole(ctx, tenantID, string(args.ID), args.Name, args.Description, m)
	if err != nil {
		return nil, err
	}
	return newRole(v), nil
}

func (r *resolver) DeleteRole(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.DeleteRole(ctx, tenantID, string(args.ID), m))
}

func (r *resolver) SetRolePermissions(ctx context.Context, args struct {
	TenantID, ID graphql.ID
	Permissions  []string
}) (*role, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	v, err := r.svc.SetRolePermissions(ctx, tenantID, string(args.ID), args.Permissions, m)
	if err != nil {
		return nil, err
	}
	return newRole(v), nil
}

// ---- sessions & audit ----

func (r *resolver) Sessions(ctx context.Context, args struct {
	TenantID graphql.ID
	UserID   *graphql.ID
	Active   *bool
	pageArgs
}) (*connection[session], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListSessions(ctx, tenantID, string(deref(args.UserID)), deref(args.Active), pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newSession, total, pg), nil
}

func (r *resolver) RevokeSession(ctx context.Context, args struct{ TenantID, ID graphql.ID }) (*bool, error) {
	tenantID, m, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	return done(r.svc.RevokeSession(ctx, tenantID, "", string(args.ID), m))
}

func (r *resolver) AuditEvents(ctx context.Context, args struct {
	TenantID      graphql.ID
	Type, ActorID *string
	pageArgs
}) (*connection[auditEvent], error) {
	tenantID, _, err := r.tenantAdmin(ctx, args.TenantID)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListAuditEvents(ctx, tenantID, store.AuditFilter{Type: deref(args.Type), ActorID: deref(args.ActorID)}, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newAuditEvent, total, pg), nil
}
