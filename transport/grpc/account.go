package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// AccountService: what a signed-in user does with their own account.

func (a *api) GetMe(ctx context.Context, _ *keyorapb.GetMeRequest) (*keyorapb.GetMeResponse, error) {
	p, _, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	u, err := a.svc.GetUser(ctx, p.TenantID, p.UserID)
	if err != nil {
		return nil, err
	}
	return &keyorapb.GetMeResponse{User: userMsg(u), Roles: p.Roles, Permissions: p.Permissions}, nil
}

func (a *api) UpdateMe(ctx context.Context, req *keyorapb.UpdateMeRequest) (*keyorapb.UpdateMeResponse, error) {
	p, m, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	if req.Name == nil {
		return nil, domain.Invalid("name", "is required")
	}
	u, err := a.svc.UpdateProfile(ctx, p, req.GetName(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UpdateMeResponse{User: userMsg(u)}, nil
}

func (a *api) ChangePassword(ctx context.Context, req *keyorapb.ChangePasswordRequest) (*keyorapb.ChangePasswordResponse, error) {
	p, m, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.svc.ChangePassword(ctx, p, req.GetCurrentPassword(), req.GetNewPassword(), m); err != nil {
		return nil, err
	}
	return &keyorapb.ChangePasswordResponse{}, nil
}

func (a *api) ListMySessions(ctx context.Context, req *keyorapb.ListMySessionsRequest) (*keyorapb.ListMySessionsResponse, error) {
	p, _, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListSessions(ctx, p.TenantID, p.UserID, true, pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListMySessionsResponse{Sessions: each(list, sessionMsg), Total: int64(total)}, nil
}

func (a *api) RevokeMySession(ctx context.Context, req *keyorapb.RevokeMySessionRequest) (*keyorapb.RevokeMySessionResponse, error) {
	p, m, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.svc.RevokeSession(ctx, p.TenantID, p.UserID, req.GetSessionId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.RevokeMySessionResponse{}, nil
}
