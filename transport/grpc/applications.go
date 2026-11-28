package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// ApplicationService. The plain-text client secret appears in exactly two
// responses: CreateApplication and RotateApplicationSecret.

// replacement turns an optional list of a partial update into the service's
// form: nil leaves the stored list alone, anything else replaces it.
func replacement(l *keyorapb.StringList) *[]string {
	if l == nil {
		return nil
	}
	values := l.GetValues()
	return &values
}

func (a *api) CreateApplication(ctx context.Context, req *keyorapb.CreateApplicationRequest) (*keyorapb.CreateApplicationResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	name, typ := req.GetName(), req.GetType()
	redirectURIs, origins := req.GetRedirectUris(), req.GetAllowedOrigins()
	app, secret, err := a.svc.CreateApplication(ctx, req.GetTenantId(), service.ApplicationInput{
		Name: &name, Type: &typ, RedirectURIs: &redirectURIs, AllowedOrigins: &origins,
		AccessTokenTTL: req.AccessTokenTtlSeconds, RefreshTokenTTL: req.RefreshTokenTtlSeconds,
	}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.CreateApplicationResponse{Application: applicationMsg(app), ClientSecret: secret}, nil
}

func (a *api) ListApplications(ctx context.Context, req *keyorapb.ListApplicationsRequest) (*keyorapb.ListApplicationsResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListApplications(ctx, req.GetTenantId(), pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListApplicationsResponse{Applications: each(list, applicationMsg), Total: int64(total)}, nil
}

func (a *api) GetApplication(ctx context.Context, req *keyorapb.GetApplicationRequest) (*keyorapb.GetApplicationResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	app, err := a.svc.GetApplication(ctx, req.GetTenantId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return &keyorapb.GetApplicationResponse{Application: applicationMsg(app)}, nil
}

func (a *api) UpdateApplication(ctx context.Context, req *keyorapb.UpdateApplicationRequest) (*keyorapb.UpdateApplicationResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	app, err := a.svc.UpdateApplication(ctx, req.GetTenantId(), req.GetId(), service.ApplicationInput{
		Name: req.Name, RedirectURIs: replacement(req.GetRedirectUris()), AllowedOrigins: replacement(req.GetAllowedOrigins()),
		AccessTokenTTL: req.AccessTokenTtlSeconds, RefreshTokenTTL: req.RefreshTokenTtlSeconds, Status: req.Status,
	}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UpdateApplicationResponse{Application: applicationMsg(app)}, nil
}

func (a *api) DeleteApplication(ctx context.Context, req *keyorapb.DeleteApplicationRequest) (*keyorapb.DeleteApplicationResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.DeleteApplication(ctx, req.GetTenantId(), req.GetId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.DeleteApplicationResponse{}, nil
}

func (a *api) RotateApplicationSecret(ctx context.Context, req *keyorapb.RotateApplicationSecretRequest) (*keyorapb.RotateApplicationSecretResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	app, secret, err := a.svc.RotateApplicationSecret(ctx, req.GetTenantId(), req.GetId(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.RotateApplicationSecretResponse{Application: applicationMsg(app), ClientSecret: secret}, nil
}
