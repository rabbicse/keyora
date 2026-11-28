package httpapi

import (
	"net/http"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

// ---- tenants (root only, except reading your own) ----

type tenantRequest struct {
	Slug   *string `json:"slug"`
	Name   *string `json:"name"`
	Status *string `json:"status"`
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request) error {
	m, err := a.root(r)
	if err != nil {
		return err
	}
	var req tenantRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	t, err := a.svc.CreateTenant(r.Context(), service.TenantInput{Slug: req.Slug, Name: req.Name}, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, t)
	return nil
}

func (a *API) listTenants(w http.ResponseWriter, r *http.Request) error {
	if _, err := a.root(r); err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	list, total, err := a.svc.ListTenants(r.Context(), pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) getTenant(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	t, err := a.svc.GetTenant(r.Context(), tenantID)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, t)
	return nil
}

func (a *API) updateTenant(w http.ResponseWriter, r *http.Request) error {
	m, err := a.root(r)
	if err != nil {
		return err
	}
	var req tenantRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Slug != nil {
		return domain.Invalid("slug", "cannot be changed after creation")
	}
	t, err := a.svc.UpdateTenant(r.Context(), r.PathValue("tenant_id"), service.TenantInput{Name: req.Name, Status: req.Status}, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, t)
	return nil
}

// ---- applications ----

type applicationRequest struct {
	Name            *string   `json:"name"`
	Type            *string   `json:"type"`
	RedirectURIs    *[]string `json:"redirect_uris"`
	AllowedOrigins  *[]string `json:"allowed_origins"`
	AccessTokenTTL  *int64    `json:"access_token_ttl_seconds"`
	RefreshTokenTTL *int64    `json:"refresh_token_ttl_seconds"`
	Status          *string   `json:"status"`
}

func (q applicationRequest) input() service.ApplicationInput {
	return service.ApplicationInput{Name: q.Name, Type: q.Type, RedirectURIs: q.RedirectURIs, AllowedOrigins: q.AllowedOrigins,
		AccessTokenTTL: q.AccessTokenTTL, RefreshTokenTTL: q.RefreshTokenTTL, Status: q.Status}
}

// applicationWithSecret is returned only by create and rotate-secret.
type applicationWithSecret struct {
	*domain.Application
	ClientSecret string `json:"client_secret,omitempty"`
}

func (a *API) createApplication(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req applicationRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, secret, err := a.svc.CreateApplication(r.Context(), tenantID, req.input(), m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, applicationWithSecret{Application: app, ClientSecret: secret})
	return nil
}

func (a *API) listApplications(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	list, total, err := a.svc.ListApplications(r.Context(), tenantID, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) getApplication(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	app, err := a.svc.GetApplication(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, app)
	return nil
}

func (a *API) updateApplication(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req applicationRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.svc.UpdateApplication(r.Context(), tenantID, r.PathValue("id"), req.input(), m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, app)
	return nil
}

func (a *API) deleteApplication(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteApplication(r.Context(), tenantID, r.PathValue("id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) rotateSecret(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	app, secret, err := a.svc.RotateApplicationSecret(r.Context(), tenantID, r.PathValue("id"), m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, applicationWithSecret{Application: app, ClientSecret: secret})
	return nil
}

// ---- users ----

type userRequest struct {
	Email         *string `json:"email"`
	Password      *string `json:"password"`
	Name          *string `json:"name"`
	Status        *string `json:"status"`
	EmailVerified *bool   `json:"email_verified"`
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req userRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	u, err := a.svc.AdminCreateUser(r.Context(), tenantID,
		service.UserInput{Email: req.Email, Password: req.Password, Name: req.Name, EmailVerified: req.EmailVerified}, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, u)
	return nil
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	list, total, err := a.svc.ListUsers(r.Context(), tenantID, store.UserFilter{Email: q.Get("email"), Status: q.Get("status")}, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	u, err := a.svc.GetUser(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, u)
	return nil
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req userRequest
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Email != nil || req.Password != nil {
		return domain.E(domain.KindInvalid, "validation_failed", "email and password cannot be changed through this endpoint")
	}
	u, err := a.svc.UpdateUser(r.Context(), tenantID, r.PathValue("id"),
		service.UserInput{Name: req.Name, Status: req.Status, EmailVerified: req.EmailVerified}, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, u)
	return nil
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteUser(r.Context(), tenantID, r.PathValue("id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) unlockUser(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	u, err := a.svc.UnlockUser(r.Context(), tenantID, r.PathValue("id"), m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, u)
	return nil
}

func (a *API) listUserRoles(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	roles, err := a.svc.ListUserRoles(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, roles)
	return nil
}

func (a *API) assignRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.AssignRole(r.Context(), tenantID, r.PathValue("id"), r.PathValue("role_id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) unassignRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.UnassignRole(r.Context(), tenantID, r.PathValue("id"), r.PathValue("role_id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- permissions & roles ----

func (a *API) createPermission(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	p, err := a.svc.CreatePermission(r.Context(), tenantID, req.Name, req.Description, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, p)
	return nil
}

func (a *API) listPermissions(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	list, total, err := a.svc.ListPermissions(r.Context(), tenantID, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) deletePermission(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeletePermission(r.Context(), tenantID, r.PathValue("id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) createRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	role, err := a.svc.CreateRole(r.Context(), tenantID, req.Name, req.Description, req.Permissions, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, role)
	return nil
}

func (a *API) listRoles(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	list, total, err := a.svc.ListRoles(r.Context(), tenantID, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) getRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	role, err := a.svc.GetRole(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, role)
	return nil
}

func (a *API) updateRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	role, err := a.svc.UpdateRole(r.Context(), tenantID, r.PathValue("id"), req.Name, req.Description, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, role)
	return nil
}

func (a *API) deleteRole(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteRole(r.Context(), tenantID, r.PathValue("id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) setRolePermissions(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	var req struct {
		Permissions *[]string `json:"permissions"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Permissions == nil {
		return domain.Invalid("permissions", "is required")
	}
	role, err := a.svc.SetRolePermissions(r.Context(), tenantID, r.PathValue("id"), *req.Permissions, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, role)
	return nil
}

// ---- sessions & audit ----

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	list, total, err := a.svc.ListSessions(r.Context(), tenantID, q.Get("user_id"), q.Get("active") == "true", pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) revokeSession(w http.ResponseWriter, r *http.Request) error {
	tenantID, m, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	if err := a.svc.RevokeSession(r.Context(), tenantID, "", r.PathValue("id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listAuditEvents(w http.ResponseWriter, r *http.Request) error {
	tenantID, _, err := a.tenantAdmin(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	list, total, err := a.svc.ListAuditEvents(r.Context(), tenantID, store.AuditFilter{Type: q.Get("type"), ActorID: q.Get("actor_id")}, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}
