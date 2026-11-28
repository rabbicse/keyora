package graphqlapi

import (
	"context"

	graphql "github.com/graph-gophers/graphql-go"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
)

// OAuth 2.0: the fields REST serves under /api/v1/oauth/. Each one is rate
// limited per field (see resolver.throttled).

type authorizeInput struct {
	ClientID, RedirectURI              string
	ResponseType, State, Scope, Nonce  *string
	CodeChallenge, CodeChallengeMethod string
	Email, Password                    string
}

// Authorize checks the user's credentials and issues an authorization code.
// The application is named, not authenticated: the code is bound to its
// registered redirect URI and to the PKCE challenge.
func (r *resolver) Authorize(ctx context.Context, args struct{ Input authorizeInput }) (*authorization, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	in := args.Input
	res, err := r.svc.AuthorizeWithPassword(ctx, service.AuthorizeRequest{
		ClientID: in.ClientID, RedirectURI: in.RedirectURI, ResponseType: deref(in.ResponseType),
		State: deref(in.State), Scope: deref(in.Scope), Nonce: deref(in.Nonce),
		CodeChallenge: in.CodeChallenge, CodeChallengeMethod: in.CodeChallengeMethod,
	}, in.Email, in.Password, c.origin, c.meta)
	if err != nil {
		return nil, err
	}
	return &authorization{Code: res.Code, State: optional(res.State), RedirectURI: res.RedirectURI, RedirectTo: res.RedirectTo,
		ExpiresIn: i32(res.ExpiresIn), Iss: res.Issuer}, nil
}

// The values of the GrantType enum.
const (
	grantAuthorizationCode = "AUTHORIZATION_CODE"
	grantRefreshToken      = "REFRESH_TOKEN"
	grantClientCredentials = "CLIENT_CREDENTIALS"
)

type tokenInput struct {
	clientArgs
	GrantType                       string
	Code, RedirectURI, CodeVerifier *string
	RefreshToken                    *string
}

// Token is the token endpoint. Confidential applications authenticate with
// their secret; public ones are identified by client ID and protected by
// PKCE. Only the client credentials grant insists on a secret.
func (r *resolver) Token(ctx context.Context, args struct{ Input tokenInput }) (*tokens, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	in := args.Input
	app, err := r.client(ctx, c, in.clientArgs, in.GrantType == grantClientCredentials)
	if err != nil {
		return nil, err
	}
	var (
		t     *service.Tokens
		scope string
	)
	switch in.GrantType {
	case grantAuthorizationCode:
		t, scope, err = r.svc.ExchangeCode(ctx, app, deref(in.Code), deref(in.RedirectURI), deref(in.CodeVerifier), c.meta)
		err = service.GrantError(err)
	case grantRefreshToken:
		t, err = r.svc.Refresh(ctx, app, deref(in.RefreshToken), c.meta)
		err = service.GrantError(err)
	case grantClientCredentials:
		t, err = r.svc.ClientCredentials(ctx, app, c.meta)
	default:
		err = domain.Invalid("grantType", "is not a supported grant")
	}
	if err != nil {
		return nil, err
	}
	return newTokens(t, scope), nil
}

// Userinfo returns the OpenID Connect claims about the user behind the
// bearer access token.
func (r *resolver) Userinfo(ctx context.Context) (*userInfo, error) {
	c, err := r.throttled(ctx)
	if err != nil {
		return nil, err
	}
	p, _, err := r.gate.User(ctx, c.bearer, c.meta)
	if err != nil {
		return nil, err
	}
	info, err := r.svc.UserInfo(ctx, p)
	if err != nil {
		return nil, err
	}
	return &userInfo{Sub: graphql.ID(info.Subject), Email: optional(info.Email), EmailVerified: info.EmailVerified, Name: optional(info.Name)}, nil
}
