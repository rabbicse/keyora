package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// RoleService: a tenant's permissions and roles.

func (a *api) CreatePermission(ctx context.Context, req *keyorapb.CreatePermissionRequest) (*keyorapb.CreatePermissionResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	p, err := a.svc.CreatePermission(ctx, req.GetTenantId(), req.GetName(), req.GetDescription(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.CreatePermissionResponse{Permission: permissionMsg(p)}, nil
}

func (a *api) ListPermissions(ctx context.Context, req *keyorapb.ListPermissionsRequest) (*keyorapb.ListPermissionsResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListPermissions(ctx, req.GetTenantId(), pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListPermissionsResponse{Permissions: each(list, permissionMsg), Total: int64(total)}, nil
}

func (a *api) DeletePermission(ctx context.Context, req *keyorapb.DeletePermissionRequest) (*keyorapb.DeletePermissionResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.DeletePermission(ctx, req.GetTenantId(), req.GetId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.DeletePermissionResponse{}, nil
}

func (a *api) CreateRole(ctx context.Context, req *keyorapb.CreateRoleRequest) (*keyorapb.CreateRoleResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	r, err := a.svc.CreateRole(ctx, req.GetTenantId(), req.GetName(), req.GetDescription(), req.GetPermissions(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.CreateRoleResponse{Role: roleMsg(r)}, nil
}

func (a *api) ListRoles(ctx context.Context, req *keyorapb.ListRolesRequest) (*keyorapb.ListRolesResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	list, total, err := a.svc.ListRoles(ctx, req.GetTenantId(), pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListRolesResponse{Roles: each(list, roleMsg), Total: int64(total)}, nil
}

func (a *api) GetRole(ctx context.Context, req *keyorapb.GetRoleRequest) (*keyorapb.GetRoleResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	r, err := a.svc.GetRole(ctx, req.GetTenantId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return &keyorapb.GetRoleResponse{Role: roleMsg(r)}, nil
}

func (a *api) UpdateRole(ctx context.Context, req *keyorapb.UpdateRoleRequest) (*keyorapb.UpdateRoleResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	r, err := a.svc.UpdateRole(ctx, req.GetTenantId(), req.GetId(), req.Name, req.Description, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UpdateRoleResponse{Role: roleMsg(r)}, nil
}

func (a *api) DeleteRole(ctx context.Context, req *keyorapb.DeleteRoleRequest) (*keyorapb.DeleteRoleResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.DeleteRole(ctx, req.GetTenantId(), req.GetId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.DeleteRoleResponse{}, nil
}

func (a *api) SetRolePermissions(ctx context.Context, req *keyorapb.SetRolePermissionsRequest) (*keyorapb.SetRolePermissionsResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	r, err := a.svc.SetRolePermissions(ctx, req.GetTenantId(), req.GetId(), req.GetPermissions(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.SetRolePermissionsResponse{Role: roleMsg(r)}, nil
}
