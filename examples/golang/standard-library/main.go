// A notes API protected by Keyora, using only the Go standard library and
// Keyora's guard package.
//
// The application plays two roles:
//
//   - Backend for a frontend: /register, /login, /refresh and /logout forward
//     to Keyora with the application's client secret attached.
//   - Resource server: /me, /notes and /reports verify the access token
//     locally against Keyora's JWKS and check permissions and roles.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/rabbicse/keyora/guard"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func main() {
	keyoraURL := env("KEYORA_URL", "http://localhost:8080")
	clientID, clientSecret := os.Getenv("KEYORA_CLIENT_ID"), os.Getenv("KEYORA_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)")
	}
	keyora := newKeyoraClient(keyoraURL, clientID, clientSecret)

	// The guard verifies signature, expiry, issuer and audience. Audience is
	// our own client_id: tokens issued to other applications are refused.
	g, err := guard.New(guard.Config{
		Issuer:   env("KEYORA_ISSUER", keyoraURL),
		Audience: clientID,
		JWKSURL:  keyoraURL + "/.well-known/jwks.json",
	})
	if err != nil {
		log.Fatal(err)
	}

	// forward relays a JSON request to Keyora and unwraps the envelope.
	forward := func(path string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
				guard.Deny(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
				return
			}
			status, res, err := keyora.post(r.Context(), path, body)
			if err != nil {
				log.Print(err)
				guard.Deny(w, http.StatusBadGateway, "identity_unavailable", "the identity service is unavailable")
				return
			}
			switch {
			case status >= 400:
				writeJSON(w, status, map[string]json.RawMessage{"error": res.Error})
			case len(res.Data) == 0:
				w.WriteHeader(status)
			default:
				writeJSON(w, status, res.Data)
			}
		}
	}

	var (
		mu    sync.Mutex
		notes = []map[string]string{{"text": "Welcome to Keyora", "author": "system"}}
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "anyone can read this"})
	})

	mux.HandleFunc("POST /register", forward("/api/v1/auth/register"))
	mux.HandleFunc("POST /login", forward("/api/v1/auth/login"))
	mux.HandleFunc("POST /refresh", forward("/api/v1/auth/refresh"))
	mux.HandleFunc("POST /logout", forward("/api/v1/auth/logout"))

	// Authentication only: any valid token.
	mux.Handle("GET /me", g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := guard.ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"sub": c.Subject, "email": c.Email, "roles": c.Roles, "permissions": c.Permissions})
	})))

	// Remote introspection: one network call per request, but it sees
	// logouts and role changes immediately.
	mux.HandleFunc("GET /me/live", func(w http.ResponseWriter, r *http.Request) {
		token, ok := guard.BearerToken(r.Header.Get("Authorization"))
		if !ok {
			guard.Deny(w, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
			return
		}
		in, err := keyora.introspect(r.Context(), token)
		if err != nil {
			log.Print(err)
			guard.Deny(w, http.StatusBadGateway, "identity_unavailable", "the identity service is unavailable")
			return
		}
		if !in.Active {
			guard.Deny(w, http.StatusUnauthorized, "invalid_token", "the access token is no longer active")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sub": in.Subject, "email": in.Email, "roles": in.Roles, "permissions": in.Permissions})
	})

	// Permission-based authorization.
	mux.Handle("GET /notes", g.Middleware(guard.RequirePermission("notes:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"notes": notes})
	}))))
	mux.Handle("POST /notes", g.Middleware(guard.RequirePermission("notes:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.Text == "" {
			guard.Deny(w, http.StatusBadRequest, "validation_failed", "text is required")
			return
		}
		c, _ := guard.ClaimsFromContext(r.Context())
		note := map[string]string{"text": in.Text, "author": c.Email}
		mu.Lock()
		notes = append(notes, note)
		mu.Unlock()
		writeJSON(w, http.StatusCreated, note)
	}))))

	// Role-based authorization.
	mux.Handle("GET /reports", g.Middleware(guard.RequireRole("editor")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]int{"total_notes": len(notes)})
	}))))

	addr := ":" + env("PORT", "9001")
	log.Printf("notes API listening on %s (Keyora at %s)", addr, keyoraURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}
