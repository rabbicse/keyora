package grpcapi

import (
	"context"
	"errors"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/transport/grpc/keyorapb"
)

// OAuthService: the authorization code flow with PKCE, the token endpoint
// and userinfo.

// Failures of the Token RPC that happen before a grant is looked at.
var (
	errTokenClient = domain.E(domain.KindUnauthenticated, "invalid_client", "client authentication failed")
	errGrantType   = domain.E(domain.KindInvalid, "unsupported_grant_type", "supported grants: authorization_code, refresh_token, client_credentials")
)

// Authorize issues an authorization code in one call: the authorization
// request and the user's credentials go in, the code comes back.
func (a *api) Authorize(ctx context.Context, req *keyorapb.AuthorizeRequest) (*keyorapb.AuthorizeResponse, error) {
	res, err := a.svc.AuthorizeWithPassword(ctx, service.AuthorizeRequest{
		ClientID: req.GetClientId(), RedirectURI: req.GetRedirectUri(), ResponseType: req.GetResponseType(),
		State: req.GetState(), Scope: req.GetScope(), Nonce: req.GetNonce(),
		CodeChallenge: req.GetCodeChallenge(), CodeChallengeMethod: req.GetCodeChallengeMethod(),
	}, req.GetEmail(), req.GetPassword(), header(ctx, "origin"), meta(ctx))
	if err != nil {
		return nil, err
	}
	return &keyorapb.AuthorizeResponse{
		Code: res.Code, State: res.State, RedirectUri: res.RedirectURI, RedirectTo: res.RedirectTo,
		ExpiresIn: res.ExpiresIn, Iss: res.Issuer,
	}, nil
}

func (a *api) Token(ctx context.Context, req *keyorapb.TokenRequest) (*keyorapb.TokenResponse, error) {
	grant := req.GetGrantType()
	switch grant {
	case "authorization_code", "refresh_token", "client_credentials":
	default:
		return nil, errGrantType
	}
	// Confidential applications authenticate with their secret; public ones
	// are identified by client_id and protected by PKCE.
	app, err := a.client(ctx, req, grant == "client_credentials")
	var de *domain.Error
	if errors.As(err, &de) && de.Kind != domain.KindInternal {
		// One answer for every application that cannot be authenticated, as
		// at the REST token endpoint.
		return nil, errTokenClient
	}
	if err != nil {
		return nil, err
	}

	// service.GrantError gives every unusable grant the same answer,
	// invalid_grant, on every transport.
	var tokens *service.Tokens
	scope := ""
	switch grant {
	case "authorization_code":
		tokens, scope, err = a.svc.ExchangeCode(ctx, app, req.GetCode(), req.GetRedirectUri(), req.GetCodeVerifier(), meta(ctx))
		err = service.GrantError(err)
	case "refresh_token":
		tokens, err = a.svc.Refresh(ctx, app, req.GetRefreshToken(), meta(ctx))
		err = service.GrantError(err)
	default:
		tokens, err = a.svc.ClientCredentials(ctx, app, meta(ctx))
	}
	if err != nil {
		return nil, err
	}
	return &keyorapb.TokenResponse{Tokens: tokensMsg(tokens), Scope: scope}, nil
}

func (a *api) UserInfo(ctx context.Context, _ *keyorapb.UserInfoRequest) (*keyorapb.UserInfoResponse, error) {
	p, _, err := a.user(ctx)
	if err != nil {
		return nil, err
	}
	info, err := a.svc.UserInfo(ctx, p)
	if err != nil {
		return nil, err
	}
	return &keyorapb.UserInfoResponse{
		Subject: info.Subject, Email: info.Email, Name: info.Name,
		EmailVerified: info.EmailVerified != nil && *info.EmailVerified,
	}, nil
}
