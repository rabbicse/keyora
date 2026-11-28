package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// TenantService: root only, except reading your own tenant.

func (a *api) CreateTenant(ctx context.Context, req *keyorapb.CreateTenantRequest) (*keyorapb.CreateTenantResponse, error) {
	m, err := a.root(ctx)
	if err != nil {
		return nil, err
	}
	slug, name := req.GetSlug(), req.GetName()
	t, err := a.svc.CreateTenant(ctx, service.TenantInput{Slug: &slug, Name: &name}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.CreateTenantResponse{Tenant: tenantMsg(t)}, nil
}

func (a *api) ListTenants(ctx context.Context, req *keyorapb.ListTenantsRequest) (*keyorapb.ListTenantsResponse, error) {
	if _, err := a.root(ctx); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListTenants(ctx, pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListTenantsResponse{Tenants: each(list, tenantMsg), Total: int64(total)}, nil
}

func (a *api) GetTenant(ctx context.Context, req *keyorapb.GetTenantRequest) (*keyorapb.GetTenantResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	t, err := a.svc.GetTenant(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	return &keyorapb.GetTenantResponse{Tenant: tenantMsg(t)}, nil
}

func (a *api) UpdateTenant(ctx context.Context, req *keyorapb.UpdateTenantRequest) (*keyorapb.UpdateTenantResponse, error) {
	m, err := a.root(ctx)
	if err != nil {
		return nil, err
	}
	t, err := a.svc.UpdateTenant(ctx, req.GetTenantId(), service.TenantInput{Name: req.Name, Status: req.Status}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UpdateTenantResponse{Tenant: tenantMsg(t)}, nil
}
