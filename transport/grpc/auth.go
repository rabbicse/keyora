package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// AuthService: registration, sign-in and token lifecycle, for callers
// identified by application credentials.

func (a *api) Register(ctx context.Context, req *keyorapb.RegisterRequest) (*keyorapb.RegisterResponse, error) {
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	in := service.RegisterInput{Email: req.GetEmail(), Password: req.GetPassword(), Name: req.GetName()}
	u, err := a.svc.Register(ctx, app, in, meta(ctx))
	if err != nil {
		return nil, err
	}
	return &keyorapb.RegisterResponse{User: userMsg(u)}, nil
}

func (a *api) Login(ctx context.Context, req *keyorapb.LoginRequest) (*keyorapb.LoginResponse, error) {
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	tokens, u, err := a.svc.Login(ctx, app, req.GetEmail(), req.GetPassword(), meta(ctx))
	if err != nil {
		return nil, err
	}
	return &keyorapb.LoginResponse{Tokens: tokensMsg(tokens), User: userMsg(u)}, nil
}

func (a *api) Refresh(ctx context.Context, req *keyorapb.RefreshRequest) (*keyorapb.RefreshResponse, error) {
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	tokens, err := a.svc.Refresh(ctx, app, req.GetRefreshToken(), meta(ctx))
	if err != nil {
		return nil, err
	}
	return &keyorapb.RefreshResponse{Tokens: tokensMsg(tokens)}, nil
}

// Logout accepts either a refresh token with application credentials, or just
// a bearer access token; both revoke the underlying session.
func (a *api) Logout(ctx context.Context, req *keyorapb.LogoutRequest) (*keyorapb.LogoutResponse, error) {
	if req.GetRefreshToken() == "" {
		p, m, err := a.user(ctx)
		if err != nil {
			return nil, err
		}
		if err := a.svc.LogoutSession(ctx, p, m); err != nil {
			return nil, err
		}
		return &keyorapb.LogoutResponse{}, nil
	}
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	if err := a.svc.Logout(ctx, app, req.GetRefreshToken(), meta(ctx)); err != nil {
		return nil, err
	}
	return &keyorapb.LogoutResponse{}, nil
}

func (a *api) Introspect(ctx context.Context, req *keyorapb.IntrospectRequest) (*keyorapb.IntrospectResponse, error) {
	app, err := a.client(ctx, req, true)
	if err != nil {
		return nil, err
	}
	res, err := a.svc.Introspect(ctx, app, req.GetToken())
	if err != nil {
		return nil, err
	}
	return &keyorapb.IntrospectResponse{
		Active: res.Active, Subject: res.Subject, TenantId: res.TenantID, ClientId: res.ClientID,
		SessionId: res.SessionID, Email: res.Email, Roles: res.Roles, Permissions: res.Permissions,
		Issuer: res.Issuer, ExpiresAt: unixTimestamp(res.ExpiresAt), IssuedAt: unixTimestamp(res.IssuedAt),
	}, nil
}

func (a *api) RequestEmailVerification(ctx context.Context, req *keyorapb.RequestEmailVerificationRequest) (*keyorapb.RequestEmailVerificationResponse, error) {
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	if err := a.svc.RequestEmailVerification(ctx, app, req.GetEmail()); err != nil {
		return nil, err
	}
	return &keyorapb.RequestEmailVerificationResponse{}, nil
}

func (a *api) ConfirmEmail(ctx context.Context, req *keyorapb.ConfirmEmailRequest) (*keyorapb.ConfirmEmailResponse, error) {
	if err := a.svc.ConfirmEmail(ctx, req.GetToken(), meta(ctx)); err != nil {
		return nil, err
	}
	return &keyorapb.ConfirmEmailResponse{}, nil
}

func (a *api) ForgotPassword(ctx context.Context, req *keyorapb.ForgotPasswordRequest) (*keyorapb.ForgotPasswordResponse, error) {
	app, err := a.client(ctx, req, false)
	if err != nil {
		return nil, err
	}
	if err := a.svc.ForgotPassword(ctx, app, req.GetEmail(), meta(ctx)); err != nil {
		return nil, err
	}
	return &keyorapb.ForgotPasswordResponse{}, nil
}

func (a *api) ResetPassword(ctx context.Context, req *keyorapb.ResetPasswordRequest) (*keyorapb.ResetPasswordResponse, error) {
	if err := a.svc.ResetPassword(ctx, req.GetToken(), req.GetNewPassword(), meta(ctx)); err != nil {
		return nil, err
	}
	return &keyorapb.ResetPasswordResponse{}, nil
}
