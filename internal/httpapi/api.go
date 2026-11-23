// Package httpapi exposes the service over a versioned REST API using only
// net/http. It contains no business rules.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
)

type Config struct {
	// AdminKey is the root management credential. Empty disables root access.
	AdminKey           string
	TrustProxyHeaders  bool
	CORSAllowedOrigins []string
	Limiter            *ratelimit.Limiter
	MetricsEnabled     bool
	HSTS               bool
	Version            string
	OpenAPI            []byte
	// LegacyClientID, when set, enables the tutorial-compatibility API. It
	// names the application whose tenant legacy registrations and logins use.
	LegacyClientID string
}

type API struct {
	svc          *service.Service
	cfg          Config
	log          *slog.Logger
	mux          *http.ServeMux
	metrics      *metrics
	adminKeyHash string
	origins      originCache
	patterns     []string
}

// Routes lists every registered "METHOD /path" pattern.
func (a *API) Routes() []string { return append([]string{}, a.patterns...) }

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func New(svc *service.Service, cfg Config, log *slog.Logger) *API {
	a := &API{svc: svc, cfg: cfg, log: log, mux: http.NewServeMux(), metrics: newMetrics()}
	if cfg.AdminKey != "" {
		a.adminKeyHash = security.HashToken(cfg.AdminKey)
	}
	a.origins.static = map[string]bool{}
	for _, o := range cfg.CORSAllowedOrigins {
		a.origins.static[o] = true
	}
	a.routes()
	return a
}

func (a *API) handle(pattern string, fn handlerFunc) {
	a.patterns = append(a.patterns, pattern)
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			a.respondError(w, r, err)
		}
	})
}

func (a *API) routes() {
	// Operations
	a.handle("GET /livez", a.livez)
	a.handle("GET /readyz", a.readyz)
	a.handle("GET /healthz", a.readyz)
	if a.cfg.MetricsEnabled {
		a.handle("GET /metrics", func(w http.ResponseWriter, _ *http.Request) error { a.metrics.write(w); return nil })
	}
	a.handle("GET /.well-known/jwks.json", a.jwks)
	a.handle("GET /api/v1/openapi.yaml", a.openapi)

	// Authentication (identified by application credentials)
	a.handle("POST /api/v1/auth/register", a.register)
	a.handle("POST /api/v1/auth/login", a.login)
	a.handle("POST /api/v1/auth/refresh", a.refresh)
	a.handle("POST /api/v1/auth/logout", a.logout)
	a.handle("POST /api/v1/auth/introspect", a.introspect)
	a.handle("POST /api/v1/auth/email-verification/request", a.requestEmailVerification)
	a.handle("POST /api/v1/auth/email-verification/confirm", a.confirmEmail)
	a.handle("POST /api/v1/auth/password/forgot", a.forgotPassword)
	a.handle("POST /api/v1/auth/password/reset", a.resetPassword)
	a.handle("GET /api/v1/oauth/authorize", a.authorizePage)
	a.handle("POST /api/v1/oauth/authorize", a.authorizeSubmit)
	a.handle("POST /api/v1/oauth/token", a.oauthToken)
	a.handle("GET /api/v1/oauth/userinfo", a.userinfo)
	a.handle("GET /.well-known/oauth-authorization-server", a.oauthMetadata)
	a.handle("GET /.well-known/openid-configuration", a.oidcDiscovery)

	if a.cfg.LegacyClientID != "" {
		a.legacyRoutes()
	}

	// Self-service (bearer access token)
	a.handle("GET /api/v1/users/me", a.me)
	a.handle("PATCH /api/v1/users/me", a.updateMe)
	a.handle("POST /api/v1/users/me/password", a.changePassword)
	a.handle("GET /api/v1/users/me/sessions", a.mySessions)
	a.handle("DELETE /api/v1/users/me/sessions/{session_id}", a.revokeMySession)

	// Management (root admin key, or a tenant administrator's access token)
	a.handle("POST /api/v1/tenants", a.createTenant)
	a.handle("GET /api/v1/tenants", a.listTenants)
	a.handle("GET /api/v1/tenants/{tenant_id}", a.getTenant)
	a.handle("PATCH /api/v1/tenants/{tenant_id}", a.updateTenant)

	const t = "/api/v1/tenants/{tenant_id}"
	a.handle("POST "+t+"/applications", a.createApplication)
	a.handle("GET "+t+"/applications", a.listApplications)
	a.handle("GET "+t+"/applications/{id}", a.getApplication)
	a.handle("PATCH "+t+"/applications/{id}", a.updateApplication)
	a.handle("DELETE "+t+"/applications/{id}", a.deleteApplication)
	a.handle("POST "+t+"/applications/{id}/rotate-secret", a.rotateSecret)

	a.handle("POST "+t+"/users", a.createUser)
	a.handle("GET "+t+"/users", a.listUsers)
	a.handle("GET "+t+"/users/{id}", a.getUser)
	a.handle("PATCH "+t+"/users/{id}", a.updateUser)
	a.handle("DELETE "+t+"/users/{id}", a.deleteUser)
	a.handle("POST "+t+"/users/{id}/unlock", a.unlockUser)
	a.handle("GET "+t+"/users/{id}/roles", a.listUserRoles)
	a.handle("PUT "+t+"/users/{id}/roles/{role_id}", a.assignRole)
	a.handle("DELETE "+t+"/users/{id}/roles/{role_id}", a.unassignRole)

	a.handle("POST "+t+"/permissions", a.createPermission)
	a.handle("GET "+t+"/permissions", a.listPermissions)
	a.handle("DELETE "+t+"/permissions/{id}", a.deletePermission)

	a.handle("POST "+t+"/roles", a.createRole)
	a.handle("GET "+t+"/roles", a.listRoles)
	a.handle("GET "+t+"/roles/{id}", a.getRole)
	a.handle("PATCH "+t+"/roles/{id}", a.updateRole)
	a.handle("DELETE "+t+"/roles/{id}", a.deleteRole)
	a.handle("PUT "+t+"/roles/{id}/permissions", a.setRolePermissions)

	a.handle("GET "+t+"/sessions", a.listSessions)
	a.handle("DELETE "+t+"/sessions/{id}", a.revokeSession)
	a.handle("GET "+t+"/audit-events", a.listAuditEvents)
}

// ---- operations ----

func (a *API) livez(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (a *API) readyz(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.svc.Store().Ping(ctx); err != nil {
		a.log.Error("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": "down"})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "up", "version": a.cfg.Version})
	return nil
}

func (a *API) jwks(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, a.svc.Keys().JWKS())
	return nil
}

func (a *API) openapi(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(a.cfg.OpenAPI)
	return nil
}

// ---- caller identification ----

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// principal authenticates the caller of a self-service or management endpoint.
func (a *API) principal(r *http.Request) (*service.Principal, service.Meta, error) {
	m := metaFrom(r)
	token := bearer(r)
	if token == "" {
		return nil, m, domain.ErrUnauthenticated
	}
	if a.adminKeyHash != "" && security.ConstantTimeEqual(security.HashToken(token), a.adminKeyHash) {
		m.ActorType, m.ActorID = "root", "admin-key"
		return &service.Principal{Root: true}, m, nil
	}
	p, err := a.svc.Authenticate(r.Context(), token)
	if err != nil {
		return nil, m, err
	}
	m.ActorType, m.ActorID = "user", p.UserID
	return p, m, nil
}

// user requires an end-user access token (the root key has no user identity).
func (a *API) user(r *http.Request) (*service.Principal, service.Meta, error) {
	p, m, err := a.principal(r)
	if err != nil {
		return nil, m, err
	}
	if p.Root {
		return nil, m, domain.E(domain.KindForbidden, "forbidden", "this endpoint requires a user access token")
	}
	return p, m, nil
}

func (a *API) root(r *http.Request) (service.Meta, error) {
	p, m, err := a.principal(r)
	if err != nil {
		return m, err
	}
	if !p.Root {
		return m, domain.ErrForbidden
	}
	return m, nil
}

// tenantAdmin authorises management of the tenant named in the path. This one
// check is the cross-tenant boundary for the entire management API.
func (a *API) tenantAdmin(r *http.Request) (string, service.Meta, error) {
	p, m, err := a.principal(r)
	if err != nil {
		return "", m, err
	}
	tenantID := r.PathValue("tenant_id")
	if !p.CanManage(tenantID) {
		return "", m, domain.ErrForbidden
	}
	return tenantID, m, nil
}

// client authenticates the calling application from HTTP Basic credentials
// or, failing that, from client_id / client_secret in the request body.
func (a *API) client(r *http.Request, bodyID, bodySecret string, requireConfidential bool) (*domain.Application, error) {
	id, secret := bodyID, bodySecret
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	return a.svc.AuthenticateClient(r.Context(), id, secret, r.Header.Get("Origin"), requireConfidential)
}
