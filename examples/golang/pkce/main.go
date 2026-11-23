// A browser sign-in using the OAuth 2.0 authorization code flow with PKCE.
//
// This application never sees the user's password: it sends the browser to
// Keyora's sign-in page and gets back a one-time code, which it exchanges for
// tokens. It is registered as a *public* application and holds no client
// secret; PKCE is what stops a stolen code from being usable by anyone else.
//
//	/          home page, shows who is signed in
//	/login     starts the flow: creates the PKCE verifier and redirects to Keyora
//	/callback  finishes it: checks state and issuer, exchanges the code
//	/logout    revokes the session at Keyora
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rabbicse/keyora/guard"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b) // 43 characters
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

var page = template.Must(template.New("home").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PKCE example</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">
<h1>Authorization code flow with PKCE</h1>
{{if .Message}}<p><strong>{{.Message}}</strong></p>{{end}}
{{if .Claims}}
<p>Signed in as <strong>{{.Claims.Email}}</strong>.</p>
<ul><li>User ID: <code>{{.Claims.Subject}}</code></li>
<li>Roles: {{range .Claims.Roles}}<code>{{.}}</code> {{else}}none{{end}}</li>
<li>Permissions: {{range .Claims.Permissions}}<code>{{.}}</code> {{else}}none{{end}}</li></ul>
<form method="post" action="/logout"><button>Sign out</button></form>
{{else}}
<p>You are not signed in.</p><p><a href="/login">Sign in with Keyora</a></p>
{{end}}
</body>`))

func main() {
	keyoraURL := env("KEYORA_URL", "http://localhost:8080")
	// The URL the *browser* uses to reach Keyora; differs from KEYORA_URL only
	// when this server reaches Keyora on an internal address.
	publicURL := env("KEYORA_PUBLIC_URL", keyoraURL)
	issuer := env("KEYORA_ISSUER", keyoraURL)
	clientID := os.Getenv("KEYORA_PKCE_CLIENT_ID")
	port := env("PORT", "9010")
	redirectURI := env("REDIRECT_URI", "http://localhost:"+port+"/callback")
	if clientID == "" {
		log.Fatal("KEYORA_PKCE_CLIENT_ID is required (run examples/setup.sh)")
	}
	g, err := guard.New(guard.Config{Issuer: issuer, Audience: clientID, JWKSURL: keyoraURL + "/.well-known/jwks.json"})
	if err != nil {
		log.Fatal(err)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}

	setCookie := func(w http.ResponseWriter, name, value string, maxAge int) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(redirectURI, "https://")})
	}
	cookie := func(r *http.Request, name string) string {
		if c, err := r.Cookie(name); err == nil {
			return c.Value
		}
		return ""
	}
	// tokenRequest posts to Keyora's token endpoint. A public client sends
	// its client_id and no secret.
	tokenRequest := func(ctx context.Context, form url.Values) (*tokens, error) {
		form.Set("client_id", clientID)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, keyoraURL+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		var t tokens
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", t.Error, t.Description)
		}
		return &t, nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Message": r.URL.Query().Get("message")}
		if access := cookie(r, "access_token"); access != "" {
			claims, err := g.Verify(r.Context(), access)
			if err != nil && cookie(r, "refresh_token") != "" {
				// Access token expired: use the refresh token once, store the rotated pair.
				if t, rerr := tokenRequest(r.Context(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cookie(r, "refresh_token")}}); rerr == nil {
					setCookie(w, "access_token", t.AccessToken, t.ExpiresIn)
					setCookie(w, "refresh_token", t.RefreshToken, 30*24*3600)
					claims, err = g.Verify(r.Context(), t.AccessToken)
				}
			}
			if err == nil {
				data["Claims"] = claims
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page.Execute(w, data)
	})

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		// A fresh verifier and state for every attempt. Both stay in this
		// browser (HttpOnly cookies); only the SHA-256 of the verifier travels
		// through the redirect.
		verifier, state := randomString(), randomString()
		sum := sha256.Sum256([]byte(verifier))
		setCookie(w, "pkce_verifier", verifier, 600)
		setCookie(w, "oauth_state", state, 600)
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"state":                 {state},
			"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"},
		}
		http.Redirect(w, r, publicURL+"/api/v1/oauth/authorize?"+q.Encode(), http.StatusFound)
	})

	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		verifier, state := cookie(r, "pkce_verifier"), cookie(r, "oauth_state")
		setCookie(w, "pkce_verifier", "", -1)
		setCookie(w, "oauth_state", "", -1)
		fail := func(msg string) { http.Redirect(w, r, "/?message="+url.QueryEscape(msg), http.StatusSeeOther) }
		switch {
		// state ties the response to the request this browser started (CSRF).
		case state == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1:
			fail("Sign-in failed: state mismatch.")
			return
		// iss (RFC 9207) proves which authorization server answered.
		case q.Get("iss") != issuer:
			fail("Sign-in failed: unexpected issuer.")
			return
		case q.Get("error") != "":
			fail("Sign-in failed: " + q.Get("error") + ".")
			return
		}
		t, err := tokenRequest(r.Context(), url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {q.Get("code")},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifier}, // proves we are the party that started the flow
		})
		if err != nil {
			log.Printf("code exchange failed: %v", err)
			fail("Sign-in failed: the code could not be exchanged.")
			return
		}
		if _, err := g.Verify(r.Context(), t.AccessToken); err != nil {
			fail("Sign-in failed: the token did not verify.")
			return
		}
		// Tokens are kept in HttpOnly cookies so page JavaScript cannot read them.
		setCookie(w, "access_token", t.AccessToken, t.ExpiresIn)
		setCookie(w, "refresh_token", t.RefreshToken, 30*24*3600)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		// Lax cookies are not sent on cross-site POSTs, so this cannot be triggered from another site.
		if refresh := cookie(r, "refresh_token"); refresh != "" {
			body, _ := json.Marshal(map[string]string{"client_id": clientID, "refresh_token": refresh})
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, keyoraURL+"/api/v1/auth/logout", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			if res, err := httpClient.Do(req); err == nil {
				res.Body.Close()
			}
		}
		setCookie(w, "access_token", "", -1)
		setCookie(w, "refresh_token", "", -1)
		http.Redirect(w, r, "/?message="+url.QueryEscape("Signed out."), http.StatusSeeOther)
	})

	log.Printf("PKCE example on http://localhost:%s (Keyora at %s, client %s)", port, keyoraURL, clientID)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
