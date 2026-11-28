package graphqlapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/service"
)

// Authentication: the fields REST serves under /api/v1/auth/. Each one is
// rate limited per field (see resolver.throttled).

func (r *resolver) Register(ctx context.Context, args struct {
	clientArgs
	Email, Password string
	Name            *string
}) (*user, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	u, err := r.svc.Register(ctx, app, service.RegisterInput{Email: args.Email, Password: args.Password, Name: deref(args.Name)}, c.meta)
	if err != nil {
		return nil, err
	}
	return newUser(u), nil
}

func (r *resolver) Login(ctx context.Context, args struct {
	clientArgs
	Email, Password string
}) (*loginResult, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	t, u, err := r.svc.Login(ctx, app, args.Email, args.Password, c.meta)
	if err != nil {
		return nil, err
	}
	return &loginResult{Tokens: newTokens(t, ""), User: newUser(u)}, nil
}

func (r *resolver) Refresh(ctx context.Context, args struct {
	clientArgs
	RefreshToken string
}) (*tokens, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	t, err := r.svc.Refresh(ctx, app, args.RefreshToken, c.meta)
	if err != nil {
		return nil, err
	}
	return newTokens(t, ""), nil
}

// Logout accepts either a refresh token with application credentials, or
// just a bearer access token; both revoke the underlying session.
func (r *resolver) Logout(ctx context.Context, args struct {
	clientArgs
	RefreshToken *string
}) (*bool, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	if deref(args.RefreshToken) == "" {
		p, m, err := r.gate.User(ctx, c.bearer, c.meta)
		if err != nil {
			return nil, err
		}
		return done(r.svc.LogoutSession(ctx, p, m))
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	return done(r.svc.Logout(ctx, app, *args.RefreshToken, c.meta))
}

func (r *resolver) IntrospectToken(ctx context.Context, args struct {
	clientArgs
	Token string
}) (*tokenIntrospection, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, true)
	if err != nil {
		return nil, err
	}
	in, err := r.svc.Introspect(ctx, app, args.Token)
	if err != nil {
		return nil, err
	}
	return newTokenIntrospection(in), nil
}

func (r *resolver) RequestEmailVerification(ctx context.Context, args struct {
	clientArgs
	Email string
}) (*bool, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	return done(r.svc.RequestEmailVerification(ctx, app, args.Email))
}

func (r *resolver) ConfirmEmail(ctx context.Context, args struct{ Token string }) (*bool, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	return done(r.svc.ConfirmEmail(ctx, args.Token, c.meta))
}

func (r *resolver) ForgotPassword(ctx context.Context, args struct {
	clientArgs
	Email string
}) (*bool, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	app, err := r.client(ctx, c, args.clientArgs, false)
	if err != nil {
		return nil, err
	}
	return done(r.svc.ForgotPassword(ctx, app, args.Email, c.meta))
}

func (r *resolver) ResetPassword(ctx context.Context, args struct{ Token, NewPassword string }) (*bool, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	return done(r.svc.ResetPassword(ctx, args.Token, args.NewPassword, c.meta))
}
