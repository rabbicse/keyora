package grpcapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

// This file reads the caller's credentials from the request metadata and
// hands them to the access gate, which makes every decision.

// meta describes the caller for the audit trail.
func meta(ctx context.Context) service.Meta {
	c := callFrom(ctx)
	return service.Meta{IP: c.ip, UserAgent: header(ctx, "user-agent"), RequestID: c.requestID}
}

// bearer extracts the bearer credential of a call, or "".
func bearer(ctx context.Context) string {
	h := header(ctx, "authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// basicAuth extracts HTTP Basic credentials from the authorization metadata.
// The standard library parses them, so they are read exactly as the REST API
// reads them.
func basicAuth(ctx context.Context) (id, secret string, ok bool) {
	r := http.Request{Header: http.Header{"Authorization": {header(ctx, "authorization")}}}
	return r.BasicAuth()
}

// user requires an end-user access token (the root key has no user identity).
func (a *api) user(ctx context.Context) (*service.Principal, service.Meta, error) {
	return a.gate.User(ctx, bearer(ctx), meta(ctx))
}

func (a *api) root(ctx context.Context) (service.Meta, error) {
	return a.gate.Root(ctx, bearer(ctx), meta(ctx))
}

// tenantAdmin authorises management of the tenant named in the request.
func (a *api) tenantAdmin(ctx context.Context, tenantID string) (service.Meta, error) {
	return a.gate.TenantAdmin(ctx, bearer(ctx), tenantID, meta(ctx))
}

// clientCredentials is implemented by every request that names the calling
// application in its fields.
type clientCredentials interface {
	GetClientId() string
	GetClientSecret() string
}

// client authenticates the calling application from Basic credentials in the
// metadata or, failing that, from client_id / client_secret in the request.
func (a *api) client(ctx context.Context, req clientCredentials, requireConfidential bool) (*domain.Application, error) {
	id, secret := req.GetClientId(), req.GetClientSecret()
	if u, p, ok := basicAuth(ctx); ok {
		id, secret = u, p
	}
	return a.gate.Client(ctx, id, secret, header(ctx, "origin"), requireConfidential)
}

// paged is implemented by every list request.
type paged interface {
	GetLimit() int32
	GetOffset() int32
}

// pageOf reads the page of a list request. A limit of 0 selects the default.
func pageOf(req paged) (store.Page, error) {
	p := store.Page{Limit: 20, Offset: int(req.GetOffset())}
	if l := req.GetLimit(); l != 0 {
		if l < 1 || l > 100 {
			return p, domain.Invalid("limit", "must be an integer between 1 and 100")
		}
		p.Limit = int(l)
	}
	if p.Offset < 0 {
		return p, domain.Invalid("offset", "must be a non-negative integer")
	}
	return p, nil
}
