// A notes API protected by Keyora, built with Gin and the keyoragin adapter.
// It exposes the same endpoints as the standard-library example.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"

	keyoragin "github.com/rabbicse/keyora/adapters/gin"
	"github.com/rabbicse/keyora/guard"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fail(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

func main() {
	keyoraURL := env("KEYORA_URL", "http://localhost:8080")
	clientID, clientSecret := os.Getenv("KEYORA_CLIENT_ID"), os.Getenv("KEYORA_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)")
	}
	keyora := newKeyoraClient(keyoraURL, clientID, clientSecret)

	g, err := guard.New(guard.Config{
		Issuer:   env("KEYORA_ISSUER", keyoraURL),
		Audience: clientID, // refuse tokens issued to other applications
		JWKSURL:  keyoraURL + "/.well-known/jwks.json",
	})
	if err != nil {
		log.Fatal(err)
	}

	// forward relays a JSON request to Keyora with the client secret attached.
	forward := func(path string) gin.HandlerFunc {
		return func(c *gin.Context) {
			var body map[string]any
			if err := c.ShouldBindJSON(&body); err != nil {
				fail(c, http.StatusBadRequest, "invalid_json", "request body must be JSON")
				return
			}
			status, res, err := keyora.post(c.Request.Context(), path, body)
			if err != nil {
				log.Print(err)
				fail(c, http.StatusBadGateway, "identity_unavailable", "the identity service is unavailable")
				return
			}
			switch {
			case status >= 400:
				c.JSON(status, gin.H{"error": json.RawMessage(res.Error)})
			case len(res.Data) == 0:
				c.Status(status)
			default:
				c.Data(status, "application/json", res.Data)
			}
		}
	}

	var (
		mu    sync.Mutex
		notes = []gin.H{{"text": "Welcome to Keyora", "author": "system"}}
	)

	gin.SetMode(env("GIN_MODE", gin.ReleaseMode))
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/public", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"message": "anyone can read this"}) })
	r.POST("/register", forward("/api/v1/auth/register"))
	r.POST("/login", forward("/api/v1/auth/login"))
	r.POST("/refresh", forward("/api/v1/auth/refresh"))
	r.POST("/logout", forward("/api/v1/auth/logout"))

	// Remote introspection: sees logouts and role changes immediately.
	r.GET("/me/live", func(c *gin.Context) {
		token, ok := guard.BearerToken(c.GetHeader("Authorization"))
		if !ok {
			fail(c, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
			return
		}
		in, err := keyora.introspect(c.Request.Context(), token)
		if err != nil {
			log.Print(err)
			fail(c, http.StatusBadGateway, "identity_unavailable", "the identity service is unavailable")
			return
		}
		if !in.Active {
			fail(c, http.StatusUnauthorized, "invalid_token", "the access token is no longer active")
			return
		}
		c.JSON(http.StatusOK, gin.H{"sub": in.Subject, "email": in.Email, "roles": in.Roles, "permissions": in.Permissions})
	})

	// Everything below requires a valid access token, verified locally.
	api := r.Group("/", keyoragin.Authenticate(g))
	api.GET("/me", func(c *gin.Context) {
		claims, _ := keyoragin.Claims(c)
		c.JSON(http.StatusOK, gin.H{"sub": claims.Subject, "email": claims.Email, "roles": claims.Roles, "permissions": claims.Permissions})
	})
	api.GET("/notes", keyoragin.RequirePermission("notes:read"), func(c *gin.Context) {
		mu.Lock()
		defer mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"notes": notes})
	})
	api.POST("/notes", keyoragin.RequirePermission("notes:write"), func(c *gin.Context) {
		var in struct {
			Text string `json:"text" binding:"required"`
		}
		if err := c.ShouldBindJSON(&in); err != nil {
			fail(c, http.StatusBadRequest, "validation_failed", "text is required")
			return
		}
		claims, _ := keyoragin.Claims(c)
		note := gin.H{"text": in.Text, "author": claims.Email}
		mu.Lock()
		notes = append(notes, note)
		mu.Unlock()
		c.JSON(http.StatusCreated, note)
	})
	api.GET("/reports", keyoragin.RequireRole("editor"), func(c *gin.Context) {
		mu.Lock()
		defer mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"total_notes": len(notes)})
	})

	addr := ":" + env("PORT", "9002")
	log.Printf("notes API (Gin) listening on %s (Keyora at %s)", addr, keyoraURL)
	log.Fatal(r.Run(addr))
}
