package graphqlapi

import (
	"context"

	graphql "github.com/graph-gophers/graphql-go"

	"github.com/rabbicse/keyora/internal/access"
	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

// resolver is the root resolver: one method per field of Query and Mutation.
// Every method identifies its caller through the gate and then makes one
// call into the service.
//
// Identification happens in each field rather than once per request because
// the fields of a mutation run in sequence and may change what the caller is
// allowed to do (logout, changePassword): the next field must see that.
type resolver struct {
	gate *access.Gate
	svc  *service.Service
}

// ---- caller identification ----

// throttled applies the credential rate limit and returns the caller. Every
// field that REST serves under /api/v1/auth/ or /api/v1/oauth/ starts with
// it. It runs once per field, so a document that repeats such a field under
// many aliases spends one unit of the caller's budget for each.
func (r *resolver) throttled(ctx context.Context) (*caller, error) {
	c := callerFrom(ctx)
	if err := r.gate.Throttle(c.meta.IP); err != nil {
		return nil, err
	}
	return c, nil
}

// clientArgs are the application credentials as arguments, for callers that
// do not send HTTP Basic.
type clientArgs struct {
	ClientID, ClientSecret *string
}

// client authenticates the calling application from HTTP Basic credentials
// or, failing that, from the clientId / clientSecret arguments.
func (r *resolver) client(ctx context.Context, c *caller, a clientArgs, requireConfidential bool) (*domain.Application, error) {
	id, secret := deref(a.ClientID), deref(a.ClientSecret)
	if c.hasBasic {
		id, secret = c.basicID, c.basicSecret
	}
	return r.gate.Client(ctx, id, secret, c.origin, requireConfidential)
}

// user requires an end-user access token.
func (r *resolver) user(ctx context.Context) (*service.Principal, service.Meta, error) {
	c := callerFrom(ctx)
	return r.gate.User(ctx, c.bearer, c.meta)
}

// root requires the root admin key.
func (r *resolver) root(ctx context.Context) (service.Meta, error) {
	c := callerFrom(ctx)
	return r.gate.Root(ctx, c.bearer, c.meta)
}

// tenantAdmin authorises management of the tenant named by an argument.
func (r *resolver) tenantAdmin(ctx context.Context, tenantID graphql.ID) (string, service.Meta, error) {
	c := callerFrom(ctx)
	m, err := r.gate.TenantAdmin(ctx, c.bearer, string(tenantID), c.meta)
	return string(tenantID), m, err
}

// ---- pagination ----

type pageArgs struct {
	Limit, Offset *int32
}

func (a pageArgs) page() (store.Page, error) {
	p := store.Page{Limit: 20}
	if a.Limit != nil {
		if *a.Limit < 1 || *a.Limit > 100 {
			return p, domain.Invalid("limit", "must be an integer between 1 and 100")
		}
		p.Limit = int(*a.Limit)
	}
	if a.Offset != nil {
		if *a.Offset < 0 {
			return p, domain.Invalid("offset", "must be a non-negative integer")
		}
		p.Offset = int(*a.Offset)
	}
	return p, nil
}

// done is the result of a mutation that has nothing to return.
func done(err error) (*bool, error) {
	if err != nil {
		return nil, err
	}
	ok := true
	return &ok, nil
}
