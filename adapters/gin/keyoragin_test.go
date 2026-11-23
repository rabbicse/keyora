package keyoragin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/rabbicse/keyora/guard"
	"github.com/rabbicse/keyora/jwt"
)

func TestGinAdapter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jwt.JWKS{Keys: []jwt.JWK{jwt.PublicJWK("k1", &key.PublicKey)}})
	}))
	defer jwks.Close()
	g, err := guard.New(guard.Config{Issuer: jwks.URL, Audience: "app-1"})
	if err != nil {
		t.Fatal(err)
	}
	token := func(perms []string, exp time.Duration) string {
		tok, _ := jwt.Signer{Key: key, KeyID: "k1"}.Sign(jwt.Claims{Issuer: jwks.URL, Subject: "user-1", Audience: jwt.Audience{"app-1"},
			ExpiresAt: time.Now().Add(exp).Unix(), Roles: []string{"editor"}, Permissions: perms})
		return tok
	}

	r := gin.New()
	api := r.Group("/", Authenticate(g))
	api.GET("/me", func(c *gin.Context) {
		claims, _ := Claims(c)
		fromCtx, _ := guard.ClaimsFromContext(c.Request.Context())
		c.JSON(200, gin.H{"sub": claims.Subject, "same": claims == fromCtx})
	})
	api.GET("/orders", RequirePermission("orders:read"), func(c *gin.Context) { c.Status(204) })
	api.GET("/admin", RequireRole("admin"), func(c *gin.Context) { c.Status(204) })
	r.GET("/unguarded", RequirePermission("orders:read"), func(c *gin.Context) { c.Status(204) })

	for name, tc := range map[string]struct {
		path, token string
		want        int
	}{
		"valid":               {"/me", token(nil, time.Hour), 200},
		"missing":             {"/me", "", 401},
		"expired":             {"/me", token(nil, -time.Minute), 401},
		"garbage":             {"/me", "x.y.z", 401},
		"permission granted":  {"/orders", token([]string{"orders:read"}, time.Hour), 204},
		"permission missing":  {"/orders", token(nil, time.Hour), 403},
		"role missing":        {"/admin", token(nil, time.Hour), 403},
		"authz without authn": {"/unguarded", token([]string{"orders:read"}, time.Hour), 401},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d (%s)", name, rec.Code, tc.want, rec.Body)
		}
		if name == "valid" && rec.Body.String() != `{"same":true,"sub":"user-1"}` {
			t.Errorf("claims not exposed consistently: %s", rec.Body)
		}
	}
}
