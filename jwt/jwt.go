// Package jwt is a deliberately small RS256-only JSON Web Token implementation
// built on the Go standard library.
//
// It supports exactly what Keyora issues: compact JWS with RSASSA-PKCS1-v1_5
// and SHA-256. "none", HMAC and every other algorithm are rejected outright,
// which removes the algorithm-confusion class of attacks by construction.
package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// MaxTokenBytes bounds the size of a token Verify will look at.
const MaxTokenBytes = 16 * 1024

const algRS256 = "RS256"

var (
	ErrMalformed   = errors.New("jwt: malformed token")
	ErrAlgorithm   = errors.New("jwt: unsupported algorithm")
	ErrUnknownKey  = errors.New("jwt: unknown signing key")
	ErrSignature   = errors.New("jwt: invalid signature")
	ErrExpired     = errors.New("jwt: token expired")
	ErrNotYetValid = errors.New("jwt: token not yet valid")
	ErrIssuer      = errors.New("jwt: unexpected issuer")
	ErrAudience    = errors.New("jwt: unexpected audience")
)

// Audience is the "aud" claim, which RFC 7519 allows to be a string or an array.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Contains reports whether aud is one of the audiences.
func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// Claims is the claim set of a Keyora access token.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`

	SessionID   string   `json:"sid,omitempty"`
	TenantID    string   `json:"tid,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`

	// TokenUse is "access" for access tokens and "id" for OpenID Connect ID
	// tokens. Both are signed by the same keys for the same audience, so an
	// API must check this to avoid accepting an ID token as an access token.
	TokenUse      string `json:"token_use,omitempty"`
	Name          string `json:"name,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	AuthTime      int64  `json:"auth_time,omitempty"`
}

// Token uses carried in the token_use claim.
const (
	UseAccess = "access"
	UseID     = "id"
)

// IsIDToken reports whether the claims belong to an OpenID Connect ID token.
func (c *Claims) IsIDToken() bool { return c.TokenUse == UseID }

// HasPermission reports whether the token carries the permission.
func (c *Claims) HasPermission(p string) bool { return contains(c.Permissions, p) }

// HasRole reports whether the token carries the role.
func (c *Claims) HasRole(r string) bool { return contains(c.Roles, r) }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid"`
}

// Signer signs tokens with one RSA key.
type Signer struct {
	Key   *rsa.PrivateKey
	KeyID string
}

var b64 = base64.RawURLEncoding

// Sign returns the compact serialization of the claims.
func (s Signer) Sign(c Claims) (string, error) {
	if s.Key == nil || s.KeyID == "" {
		return "", errors.New("jwt: signer needs a key and key id")
	}
	h, err := json.Marshal(header{Alg: algRS256, Typ: "JWT", Kid: s.KeyID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, s.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// KeyFunc resolves a key ID to a public key.
type KeyFunc func(kid string) (*rsa.PublicKey, bool)

// Validation describes what a token must satisfy beyond a valid signature.
// Empty Issuer or Audience skips that check; expiry is always enforced.
type Validation struct {
	Issuer   string
	Audience string
	Now      func() time.Time
	Leeway   time.Duration
}

// Verify checks the signature first and only then trusts and validates the claims.
func Verify(token string, keys KeyFunc, v Validation) (*Claims, error) {
	if len(token) > MaxTokenBytes {
		return nil, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrMalformed
	}
	hb, err := b64.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ErrMalformed
	}
	if h.Alg != algRS256 {
		return nil, ErrAlgorithm
	}
	pub, ok := keys(h.Kid)
	if !ok || pub == nil {
		return nil, ErrUnknownKey
	}
	sig, err := b64.Strict().DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, ErrSignature
	}
	pb, err := b64.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, ErrMalformed
	}

	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.ExpiresAt == 0 || !now.Before(time.Unix(c.ExpiresAt, 0).Add(v.Leeway)) {
		return nil, ErrExpired
	}
	if c.NotBefore != 0 && now.Add(v.Leeway).Before(time.Unix(c.NotBefore, 0)) {
		return nil, ErrNotYetValid
	}
	if v.Issuer != "" && c.Issuer != v.Issuer {
		return nil, ErrIssuer
	}
	if v.Audience != "" && !c.Audience.Contains(v.Audience) {
		return nil, ErrAudience
	}
	return &c, nil
}
