package grpcapi

import (
	"context"

	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// UserService: a tenant's users and their role assignments.

func (a *api) CreateUser(ctx context.Context, req *keyorapb.CreateUserRequest) (*keyorapb.CreateUserResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	email, pw, name, verified := req.GetEmail(), req.GetPassword(), req.GetName(), req.GetEmailVerified()
	u, err := a.svc.AdminCreateUser(ctx, req.GetTenantId(),
		service.UserInput{Email: &email, Password: &pw, Name: &name, EmailVerified: &verified}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.CreateUserResponse{User: userMsg(u)}, nil
}

func (a *api) ListUsers(ctx context.Context, req *keyorapb.ListUsersRequest) (*keyorapb.ListUsersResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pg, err := pageOf(req)
	if err != nil {
		return nil, err
	}
	filter := store.UserFilter{Email: req.GetEmail(), Status: req.GetStatus()}
	list, total, err := a.svc.ListUsers(ctx, req.GetTenantId(), filter, pg)
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListUsersResponse{Users: each(list, userMsg), Total: int64(total)}, nil
}

func (a *api) GetUser(ctx context.Context, req *keyorapb.GetUserRequest) (*keyorapb.GetUserResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	u, err := a.svc.GetUser(ctx, req.GetTenantId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return &keyorapb.GetUserResponse{User: userMsg(u)}, nil
}

func (a *api) UpdateUser(ctx context.Context, req *keyorapb.UpdateUserRequest) (*keyorapb.UpdateUserResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	u, err := a.svc.UpdateUser(ctx, req.GetTenantId(), req.GetId(),
		service.UserInput{Name: req.Name, Status: req.Status, EmailVerified: req.EmailVerified}, m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UpdateUserResponse{User: userMsg(u)}, nil
}

func (a *api) DeleteUser(ctx context.Context, req *keyorapb.DeleteUserRequest) (*keyorapb.DeleteUserResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.DeleteUser(ctx, req.GetTenantId(), req.GetId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.DeleteUserResponse{}, nil
}

func (a *api) UnlockUser(ctx context.Context, req *keyorapb.UnlockUserRequest) (*keyorapb.UnlockUserResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	u, err := a.svc.UnlockUser(ctx, req.GetTenantId(), req.GetId(), m)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UnlockUserResponse{User: userMsg(u)}, nil
}

func (a *api) ListUserRoles(ctx context.Context, req *keyorapb.ListUserRolesRequest) (*keyorapb.ListUserRolesResponse, error) {
	if _, err := a.tenantAdmin(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	roles, err := a.svc.ListUserRoles(ctx, req.GetTenantId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	return &keyorapb.ListUserRolesResponse{Roles: each(roles, roleMsg)}, nil
}

func (a *api) AssignUserRole(ctx context.Context, req *keyorapb.AssignUserRoleRequest) (*keyorapb.AssignUserRoleResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.AssignRole(ctx, req.GetTenantId(), req.GetUserId(), req.GetRoleId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.AssignUserRoleResponse{}, nil
}

func (a *api) UnassignUserRole(ctx context.Context, req *keyorapb.UnassignUserRoleRequest) (*keyorapb.UnassignUserRoleResponse, error) {
	m, err := a.tenantAdmin(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := a.svc.UnassignRole(ctx, req.GetTenantId(), req.GetUserId(), req.GetRoleId(), m); err != nil {
		return nil, err
	}
	return &keyorapb.UnassignUserRoleResponse{}, nil
}
