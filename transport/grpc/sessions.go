package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// SessionService and AuditService: a tenant's sessions and its audit trail.

func (a *api) ListSessions(ctx context.Context, req *keyorapb.ListSessionsRequest) (*keyorapb.ListSessionsResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListSessions(ctx, req.GetTenantId(), req.GetUserId(), req.GetActiveOnly(), pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListSessionsResponse{Sessions: each(list, sessionMsg), Total: int64(total)}, nil
}

func (a *api) RevokeSession(ctx context.Context, req *keyorapb.RevokeSessionRequest) (*keyorapb.RevokeSessionResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	// An empty user ID: an administrator may end any session of the tenant.
	if err := a.svc.RevokeSession(ctx, req.GetTenantId(), "", req.GetId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.RevokeSessionResponse{}, nil
}

func (a *api) ListAuditEvents(ctx context.Context, req *keyorapb.ListAuditEventsRequest) (*keyorapb.ListAuditEventsResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	filter := store.AuditFilter{Type: req.GetType(), ActorID: req.GetActorId()}
	list, total, err := a.svc.ListAuditEvents(ctx, req.GetTenantId(), filter, pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListAuditEventsResponse{Events: each(list, auditEventMsg), Total: int64(total)}, nil
}
