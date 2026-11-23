// Package domain holds Keyora's core entities and error vocabulary. It has no
// knowledge of HTTP, SQL or any framework.
package domain

import "errors"

// Kind classifies an error so delivery layers can map it to a transport status.
type Kind int

const (
	KindInternal Kind = iota
	KindInvalid
	KindUnauthenticated
	KindForbidden
	KindNotFound
	KindConflict
	KindLocked
	KindRateLimited
)

// Error is a stable, machine-readable error. Code is part of the public API.
type Error struct {
	Kind    Kind
	Code    string
	Message string
	Details map[string]string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is matches on Code so wrapped or re-created errors compare equal.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Code == e.Code
}

// E builds an Error.
func E(kind Kind, code, message string) *Error {
	return &Error{Kind: kind, Code: code, Message: message}
}

// Invalid builds a validation error pointing at one field.
func Invalid(field, message string) *Error {
	return &Error{Kind: KindInvalid, Code: "validation_failed", Message: "request validation failed",
		Details: map[string]string{field: message}}
}

var (
	ErrNotFound = E(KindNotFound, "not_found", "resource not found")
	ErrConflict = E(KindConflict, "conflict", "resource already exists")

	ErrInvalidCredentials  = E(KindUnauthenticated, "invalid_credentials", "invalid email or password")
	ErrInvalidClient       = E(KindUnauthenticated, "invalid_client", "client authentication failed")
	ErrInvalidToken        = E(KindUnauthenticated, "invalid_token", "token is invalid or expired")
	ErrInvalidRefreshToken = E(KindUnauthenticated, "invalid_refresh_token", "refresh token is invalid or expired")
	ErrRefreshTokenReused  = E(KindUnauthenticated, "refresh_token_reused", "refresh token was already used; the session has been revoked")
	ErrUnauthenticated     = E(KindUnauthenticated, "unauthenticated", "authentication required")
	ErrForbidden           = E(KindForbidden, "forbidden", "you do not have permission to perform this action")
	ErrOriginNotAllowed    = E(KindForbidden, "origin_not_allowed", "request origin is not allowed for this application")
	ErrAccountLocked       = E(KindLocked, "account_locked", "account is temporarily locked after too many failed sign-in attempts")
	ErrAccountDisabled     = E(KindForbidden, "account_disabled", "account is disabled")
	ErrEmailNotVerified    = E(KindForbidden, "email_not_verified", "email address has not been verified")
	ErrEmailTaken          = E(KindConflict, "email_taken", "an account with this email already exists")
	ErrRateLimited         = E(KindRateLimited, "rate_limited", "too many requests")
	ErrUnstorable          = E(KindInvalid, "invalid_input", "input contains characters that cannot be stored")
	ErrInvalidGrant        = E(KindInvalid, "invalid_grant", "authorization code is invalid, expired, already used, or does not match this request")
	ErrInvalidRedirectURI  = E(KindInvalid, "invalid_redirect_uri", "redirect_uri is not registered for this application")
	ErrInvalidVerification = E(KindInvalid, "invalid_verification_token", "verification token is invalid or expired")
)
