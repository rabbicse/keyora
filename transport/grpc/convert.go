package grpcapi

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// This file turns domain values into API messages. Messages are built field
// by field, so a stored secret (a password hash, a client secret hash) cannot
// reach a client by being added to a domain type.

func timestamp(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// optionalTimestamp leaves the field unset for a nil time.
func optionalTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// unixTimestamp converts a JWT NumericDate, leaving the field unset for 0.
func unixTimestamp(secs int64) *timestamppb.Timestamp {
	if secs == 0 {
		return nil
	}
	return timestamppb.New(time.Unix(secs, 0))
}

// each converts a slice of domain values.
func each[T, M any](in []T, convert func(T) M) []M {
	out := make([]M, len(in))
	for i, v := range in {
		out[i] = convert(v)
	}
	return out
}

func tenantMsg(t *domain.Tenant) *keyorapb.Tenant {
	return &keyorapb.Tenant{
		Id: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status,
		CreatedAt: timestamp(t.CreatedAt), UpdatedAt: timestamp(t.UpdatedAt),
	}
}

func applicationMsg(a *domain.Application) *keyorapb.Application {
	return &keyorapb.Application{
		Id: a.ID, TenantId: a.TenantID, Name: a.Name, Type: a.Type, ClientId: a.ClientID,
		RedirectUris: a.RedirectURIs, AllowedOrigins: a.AllowedOrigins,
		AccessTokenTtlSeconds: a.AccessTokenTTL, RefreshTokenTtlSeconds: a.RefreshTokenTTL,
		Status: a.Status, CreatedAt: timestamp(a.CreatedAt), UpdatedAt: timestamp(a.UpdatedAt),
	}
}

func userMsg(u *domain.User) *keyorapb.User {
	return &keyorapb.User{
		Id: u.ID, TenantId: u.TenantID, Email: u.Email, Name: u.Name, Status: u.Status,
		EmailVerified: u.EmailVerified,
		LockedUntil:   optionalTimestamp(u.LockedUntil), LastLoginAt: optionalTimestamp(u.LastLoginAt),
		CreatedAt: timestamp(u.CreatedAt), UpdatedAt: timestamp(u.UpdatedAt),
	}
}

func permissionMsg(p *domain.Permission) *keyorapb.Permission {
	return &keyorapb.Permission{
		Id: p.ID, TenantId: p.TenantID, Name: p.Name, Description: p.Description,
		CreatedAt: timestamp(p.CreatedAt),
	}
}

func roleMsg(r *domain.Role) *keyorapb.Role {
	return &keyorapb.Role{
		Id: r.ID, TenantId: r.TenantID, Name: r.Name, Description: r.Description, Permissions: r.Permissions,
		CreatedAt: timestamp(r.CreatedAt), UpdatedAt: timestamp(r.UpdatedAt),
	}
}

func sessionMsg(s *domain.Session) *keyorapb.Session {
	return &keyorapb.Session{
		Id: s.ID, TenantId: s.TenantID, UserId: s.UserID, ApplicationId: s.ApplicationID,
		Ip: s.IP, UserAgent: s.UserAgent,
		CreatedAt: timestamp(s.CreatedAt), LastUsedAt: timestamp(s.LastUsedAt),
		ExpiresAt: timestamp(s.ExpiresAt), RevokedAt: optionalTimestamp(s.RevokedAt),
	}
}

func auditEventMsg(e *domain.AuditEvent) *keyorapb.AuditEvent {
	return &keyorapb.AuditEvent{
		Id: e.ID, TenantId: e.TenantID, Type: e.Type, ActorType: e.ActorType, ActorId: e.ActorID,
		TargetId: e.TargetID, Ip: e.IP, UserAgent: e.UserAgent, RequestId: e.RequestID,
		Metadata: e.Metadata, CreatedAt: timestamp(e.CreatedAt),
	}
}

func tokensMsg(t *service.Tokens) *keyorapb.Tokens {
	return &keyorapb.Tokens{
		AccessToken: t.AccessToken, TokenType: t.TokenType, ExpiresIn: t.ExpiresIn,
		RefreshToken: t.RefreshToken, RefreshExpiresIn: t.RefreshExpiresIn,
		SessionId: t.SessionID, IdToken: t.IDToken,
	}
}
