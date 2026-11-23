// Package guard protects a Go service with Keyora access tokens.
//
// It verifies tokens locally against Keyora's published JWKS (no network
// call per request) and offers net/http middleware plus role and permission
// checks. It uses only the Go standard library.
//
//	g, err := guard.New(guard.Config{
//		Issuer:   "https://id.example.com",
//		Audience: os.Getenv("KEYORA_CLIENT_ID"),
//	})
//	mux.Handle("GET /orders", g.Middleware(guard.RequirePermission("orders:read")(ordersHandler)))
package guard

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

type Config struct {
	// Issuer is Keyora's KEYORA_ISSUER value. Required.
	Issuer string
	// Audience is the client_id of the application whose tokens this
	// service accepts. Required: without it, a token issued to any other
	// application of the same Keyora would be accepted.
	Audience string
	// JWKSURL defaults to Issuer + "/.well-known/jwks.json". Set it when the
	// service reaches Keyora on an internal address that differs from the issuer.
	JWKSURL string
	// HTTPClient defaults to a client with a 5 second timeout.
	HTTPClient *http.Client
	// CacheTTL is how long keys are cached. Default 5 minutes.
	CacheTTL time.Duration
	// Leeway tolerates clock skew between this service and Keyora.
	Leeway time.Duration
}

// minRefetch bounds how often an unknown key ID may trigger a JWKS fetch, so
// tokens with made-up key IDs cannot be used to hammer Keyora.
const minRefetch = 30 * time.Second

type Guard struct {
	cfg Config

	mu      sync.Mutex
	keys    jwt.KeyFunc
	fetched time.Time
	now     func() time.Time
}

func New(cfg Config) (*Guard, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("guard: Issuer and Audience are required")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = cfg.Issuer + "/.well-known/jwks.json"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &Guard{cfg: cfg, now: time.Now}, nil
}

func (g *Guard) fetch(ctx context.Context) (jwt.KeyFunc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := g.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guard: JWKS endpoint returned %d", res.StatusCode)
	}
	var set jwt.JWKS
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("guard: invalid JWKS: %w", err)
	}
	return set.KeyFunc(), nil
}

// key resolves a key ID, refreshing the cached set when it is stale or when
// the ID is unknown (which is what a key rotation looks like).
func (g *Guard) key(ctx context.Context, kid string) (*rsa.PublicKey, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	age := g.now().Sub(g.fetched)
	if g.keys != nil && age < g.cfg.CacheTTL {
		if k, ok := g.keys(kid); ok || age < minRefetch {
			return k, ok
		}
	}
	if g.keys == nil || age >= minRefetch {
		fresh, err := g.fetch(ctx)
		if err == nil {
			g.keys, g.fetched = fresh, g.now()
		} else if g.keys == nil {
			return nil, false
		}
		// On a failed refresh keep serving the last known keys: an outage
		// of Keyora should not take every dependent service down with it.
	}
	return g.keys(kid)
}

// Verify checks the signature, expiry, issuer and audience of an access token.
func (g *Guard) Verify(ctx context.Context, token string) (*jwt.Claims, error) {
	c, err := jwt.Verify(token, func(kid string) (*rsa.PublicKey, bool) { return g.key(ctx, kid) },
		jwt.Validation{Issuer: g.cfg.Issuer, Audience: g.cfg.Audience, Now: g.now, Leeway: g.cfg.Leeway})
	if err != nil {
		return nil, err
	}
	// An ID token tells a client who signed in; it is not a credential for APIs.
	if c.IsIDToken() {
		return nil, ErrIDToken
	}
	return c, nil
}

// ErrIDToken is returned when an OpenID Connect ID token is presented where
// an access token is required.
var ErrIDToken = errors.New("guard: ID tokens are not accepted as access tokens")

type ctxKey struct{}

// WithClaims stores claims in a context; adapters for other routers use it.
func WithClaims(ctx context.Context, c *jwt.Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFromContext returns the verified claims of the current request.
func ClaimsFromContext(ctx context.Context) (*jwt.Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*jwt.Claims)
	return c, ok
}

// BearerToken extracts the token from an Authorization header value.
func BearerToken(header string) (string, bool) {
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		if t := strings.TrimSpace(header[7:]); t != "" {
			return t, true
		}
	}
	return "", false
}

// Deny writes the JSON error body used by the middleware in this package.
func Deny(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// Middleware rejects requests without a valid access token (401) and makes
// the claims of valid ones available through ClaimsFromContext.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r.Header.Get("Authorization"))
		if !ok {
			Deny(w, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
			return
		}
		claims, err := g.Verify(r.Context(), token)
		if err != nil {
			code := "invalid_token"
			if errors.Is(err, jwt.ErrExpired) {
				code = "token_expired" // the client should refresh and retry
			}
			Deny(w, http.StatusUnauthorized, code, "the access token is invalid or expired")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

func require(check func(*jwt.Claims) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				Deny(w, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
				return
			}
			if !check(claims) {
				Deny(w, http.StatusForbidden, "forbidden", "you do not have permission to perform this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission allows only tokens carrying every listed permission (403
// otherwise). It must run inside Middleware.
func RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return require(func(c *jwt.Claims) bool {
		for _, p := range permissions {
			if !c.HasPermission(p) {
				return false
			}
		}
		return true
	})
}

// RequireRole allows only tokens carrying at least one of the listed roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return require(func(c *jwt.Claims) bool {
		for _, r := range roles {
			if c.HasRole(r) {
				return true
			}
		}
		return false
	})
}
