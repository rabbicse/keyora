package graphqlapi

import (
	"context"

	graphql "github.com/graph-gophers/graphql-go"
)

// Self-service: the fields REST serves under /api/v1/users/me. They act on
// the user behind the bearer access token and on nobody else.

func (r *resolver) Me(ctx context.Context) (*profile, error) {
	p, _, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.GetUser(ctx, p.TenantID, p.UserID)
	if err != nil {
		return nil, err
	}
	return &profile{User: newUser(u), Roles: p.Roles, Permissions: p.Permissions}, nil
}

func (r *resolver) UpdateMe(ctx context.Context, args struct{ Name string }) (*user, error) {
	p, m, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.UpdateProfile(ctx, p, args.Name, m)
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) ChangePassword(ctx context.Context, args struct{ CurrentPassword, NewPassword string }) (*bool, error) {
	p, m, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	return done(r.svc.ChangePassword(ctx, p, args.CurrentPassword, args.NewPassword, m))
}

func (r *resolver) MySessions(ctx context.Context, args pageArgs) (*connection[session], error) {
	p, _, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	pg, err := args.page()
	if err != nil {
		return nil, err
	}
	items, total, err := r.svc.ListSessions(ctx, p.TenantID, p.UserID, true, pg)
	if err != nil {
		return nil, err
	}
	return newConnection(items, newSession, total, pg), nil
}

func (r *resolver) RevokeMySession(ctx context.Context, args struct{ SessionID graphql.ID }) (*bool, error) {
	p, m, err := r.user(ctx)
	if err != nil {
		return nil, err
	}
	return done(r.svc.RevokeSession(ctx, p.TenantID, p.UserID, string(args.SessionID), m))
}
