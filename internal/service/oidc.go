package service

import (
	"context"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/jwt"
)

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// issueIDToken mints an OpenID Connect ID token (OIDC Core section 2) for a
// code that was requested with the openid scope. The email and profile scopes
// decide which user claims it carries. It has the same lifetime as the access
// token and is marked token_use=id so APIs can refuse it.
func (s *Service) issueIDToken(app *domain.Application, u *domain.User, sess *domain.Session, ac *domain.AuthorizationCode) (string, error) {
	now := s.now()
	c := jwt.Claims{
		Issuer: s.opt.Issuer, Subject: u.ID, Audience: jwt.Audience{app.ClientID},
		ExpiresAt: now.Add(time.Duration(app.AccessTokenTTL) * time.Second).Unix(), IssuedAt: now.Unix(),
		ID: security.NewID(), SessionID: sess.ID, TokenUse: jwt.UseID,
		Nonce: ac.Nonce, AuthTime: sess.CreatedAt.Unix(),
	}
	if hasScope(ac.Scope, "email") {
		verified := u.EmailVerified
		c.Email, c.EmailVerified = u.Email, &verified
	}
	if hasScope(ac.Scope, "profile") {
		c.Name = u.Name
	}
	return s.keys.Signer().Sign(c)
}

// UserInfo is the OpenID Connect userinfo response.
type UserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// UserInfo returns the claims about the user behind an access token.
func (s *Service) UserInfo(ctx context.Context, p *Principal) (*UserInfo, error) {
	u, err := s.store.GetUser(ctx, p.TenantID, p.UserID)
	if err != nil {
		return nil, err
	}
	verified := u.EmailVerified
	return &UserInfo{Subject: u.ID, Email: u.Email, EmailVerified: &verified, Name: u.Name}, nil
}
