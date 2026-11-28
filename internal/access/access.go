// Package access decides who is calling. Every transport (REST, GraphQL,
// gRPC) identifies its callers through a Gate, so the rules about who may
// manage which tenant, and the limit on credential guessing, exist exactly
// once and cannot drift apart between transports.
package access

import (
	"context"
	"strconv"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
)

type Gate struct {
	svc          *service.Service
	adminKeyHash string
	limiter      *ratelimit.Limiter
}

// New builds a Gate. An empty adminKey disables root access; a nil limiter
// disables throttling.
func New(svc *service.Service, adminKey string, limiter *ratelimit.Limiter) *Gate {
	g := &Gate{svc: svc, limiter: limiter}
	if adminKey != "" {
		g.adminKeyHash = security.HashToken(adminKey)
	}
	return g
}

// Service is the service the gate protects.
func (g *Gate) Service() *service.Service { return g.svc }

// Principal authenticates a bearer credential: the root admin key or a
// user's access token. The returned Meta names the actor for the audit log.
func (g *Gate) Principal(ctx context.Context, token string, m service.Meta) (*service.Principal, service.Meta, error) {
	if token == "" {
		return nil, m, domain.ErrUnauthenticated
	}
	if g.adminKeyHash != "" && security.ConstantTimeEqual(security.HashToken(token), g.adminKeyHash) {
		m.ActorType, m.ActorID = "root", "admin-key"
		return &service.Principal{Root: true}, m, nil
	}
	p, err := g.svc.Authenticate(ctx, token)
	if err != nil {
		return nil, m, err
	}
	m.ActorType, m.ActorID = "user", p.UserID
	return p, m, nil
}

// User requires an end-user access token (the root key has no user identity).
func (g *Gate) User(ctx context.Context, token string, m service.Meta) (*service.Principal, service.Meta, error) {
	p, m, err := g.Principal(ctx, token, m)
	if err != nil {
		return nil, m, err
	}
	if p.Root {
		return nil, m, domain.E(domain.KindForbidden, "forbidden", "this operation requires a user access token")
	}
	return p, m, nil
}

// Root requires the root admin key.
func (g *Gate) Root(ctx context.Context, token string, m service.Meta) (service.Meta, error) {
	p, m, err := g.Principal(ctx, token, m)
	if err != nil {
		return m, err
	}
	if !p.Root {
		return m, domain.ErrForbidden
	}
	return m, nil
}

// TenantAdmin authorises management of one tenant. This one check is the
// cross-tenant boundary for the entire management API, on every transport.
func (g *Gate) TenantAdmin(ctx context.Context, token, tenantID string, m service.Meta) (service.Meta, error) {
	p, m, err := g.Principal(ctx, token, m)
	if err != nil {
		return m, err
	}
	if tenantID == "" || !p.CanManage(tenantID) {
		return m, domain.ErrForbidden
	}
	return m, nil
}

// Client authenticates the calling application. origin is the browser's
// Origin header, empty for other callers.
func (g *Gate) Client(ctx context.Context, clientID, secret, origin string, requireConfidential bool) (*domain.Application, error) {
	return g.svc.AuthenticateClient(ctx, clientID, secret, origin, requireConfidential)
}

// Throttle applies the per-address limit that protects the operations taking
// credentials (sign-in, registration, token and code requests). Transports
// call it before any such operation; all of them share one budget per address.
func (g *Gate) Throttle(ip string) error {
	ok, wait := g.limiter.Allow(ip)
	if ok {
		return nil
	}
	e := *domain.ErrRateLimited
	e.Details = map[string]string{"retry_after_seconds": strconv.Itoa(int(wait.Seconds()) + 1)}
	return &e
}
