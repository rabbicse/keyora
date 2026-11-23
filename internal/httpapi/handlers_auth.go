package httpapi

import (
	"net/http"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/service"
)

type clientFields struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type loginResponse struct {
	*service.Tokens
	User *domain.User `json:"user"`
}

func (a *API) register(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	u, err := a.svc.Register(r.Context(), app, service.RegisterInput{Email: req.Email, Password: req.Password, Name: req.Name}, metaFrom(r))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusCreated, u)
	return nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	tokens, u, err := a.svc.Login(r.Context(), app, req.Email, req.Password, metaFrom(r))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, loginResponse{Tokens: tokens, User: u})
	return nil
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		RefreshToken string `json:"refresh_token"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	tokens, err := a.svc.Refresh(r.Context(), app, req.RefreshToken, metaFrom(r))
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, tokens)
	return nil
}

// logout accepts either a refresh token with application credentials, or just
// a bearer access token; both revoke the underlying session.
func (a *API) logout(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		RefreshToken string `json:"refresh_token"`
	}
	if r.ContentLength != 0 {
		if err := decode(w, r, &req); err != nil {
			return err
		}
	}
	if req.RefreshToken == "" {
		p, m, err := a.user(r)
		if err != nil {
			return err
		}
		if err := a.svc.LogoutSession(r.Context(), p, m); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	if err := a.svc.Logout(r.Context(), app, req.RefreshToken, metaFrom(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) introspect(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		Token string `json:"token"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return err
	}
	res, err := a.svc.Introspect(r.Context(), app, req.Token)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, res)
	return nil
}

func (a *API) requestEmailVerification(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		Email string `json:"email"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	if err := a.svc.RequestEmailVerification(r.Context(), app, req.Email); err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (a *API) confirmEmail(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if err := a.svc.ConfirmEmail(r.Context(), req.Token, metaFrom(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) forgotPassword(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		clientFields
		Email string `json:"email"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	app, err := a.client(r, req.ClientID, req.ClientSecret, false)
	if err != nil {
		return err
	}
	if err := a.svc.ForgotPassword(r.Context(), app, req.Email, metaFrom(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (a *API) resetPassword(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if err := a.svc.ResetPassword(r.Context(), req.Token, req.NewPassword, metaFrom(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- self-service ----

type profile struct {
	*domain.User
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (a *API) me(w http.ResponseWriter, r *http.Request) error {
	p, _, err := a.user(r)
	if err != nil {
		return err
	}
	u, err := a.svc.GetUser(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, profile{User: u, Roles: orEmpty(p.Roles), Permissions: orEmpty(p.Permissions)})
	return nil
}

func (a *API) updateMe(w http.ResponseWriter, r *http.Request) error {
	p, m, err := a.user(r)
	if err != nil {
		return err
	}
	var req struct {
		Name *string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.Name == nil {
		return domain.Invalid("name", "is required")
	}
	u, err := a.svc.UpdateProfile(r.Context(), p, *req.Name, m)
	if err != nil {
		return err
	}
	respond(w, r, http.StatusOK, u)
	return nil
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) error {
	p, m, err := a.user(r)
	if err != nil {
		return err
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if err := a.svc.ChangePassword(r.Context(), p, req.CurrentPassword, req.NewPassword, m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) mySessions(w http.ResponseWriter, r *http.Request) error {
	p, _, err := a.user(r)
	if err != nil {
		return err
	}
	pg, err := pageFrom(r)
	if err != nil {
		return err
	}
	list, total, err := a.svc.ListSessions(r.Context(), p.TenantID, p.UserID, true, pg)
	if err != nil {
		return err
	}
	respondPage(w, r, list, pg, total)
	return nil
}

func (a *API) revokeMySession(w http.ResponseWriter, r *http.Request) error {
	p, m, err := a.user(r)
	if err != nil {
		return err
	}
	if err := a.svc.RevokeSession(r.Context(), p.TenantID, p.UserID, r.PathValue("session_id"), m); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
