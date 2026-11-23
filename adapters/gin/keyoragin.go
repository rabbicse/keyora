// Package keyoragin adapts github.com/rabbicse/keyora/guard to the Gin web
// framework. It is a separate Go module so that Gin never becomes a
// dependency of the Keyora core.
package keyoragin

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rabbicse/keyora/guard"
	"github.com/rabbicse/keyora/jwt"
)

const claimsKey = "keyora.claims"

func deny(c *gin.Context, status int, code, message string) {
	if status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", `Bearer error="`+code+`"`)
	}
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

// Authenticate rejects requests without a valid Keyora access token (401)
// and stores the verified claims for later handlers.
func Authenticate(g *guard.Guard) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := guard.BearerToken(c.GetHeader("Authorization"))
		if !ok {
			deny(c, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
			return
		}
		claims, err := g.Verify(c.Request.Context(), token)
		if err != nil {
			code := "invalid_token"
			if errors.Is(err, jwt.ErrExpired) {
				code = "token_expired"
			}
			deny(c, http.StatusUnauthorized, code, "the access token is invalid or expired")
			return
		}
		c.Set(claimsKey, claims)
		c.Request = c.Request.WithContext(guard.WithClaims(c.Request.Context(), claims))
		c.Next()
	}
}

// Claims returns the verified claims of the current request.
func Claims(c *gin.Context) (*jwt.Claims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*jwt.Claims)
	return claims, ok
}

func require(check func(*jwt.Claims) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := Claims(c)
		if !ok {
			deny(c, http.StatusUnauthorized, "missing_token", "a bearer access token is required")
			return
		}
		if !check(claims) {
			deny(c, http.StatusForbidden, "forbidden", "you do not have permission to perform this action")
			return
		}
		c.Next()
	}
}

// RequirePermission allows only tokens carrying every listed permission.
func RequirePermission(permissions ...string) gin.HandlerFunc {
	return require(func(cl *jwt.Claims) bool {
		for _, p := range permissions {
			if !cl.HasPermission(p) {
				return false
			}
		}
		return true
	})
}

// RequireRole allows only tokens carrying at least one of the listed roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	return require(func(cl *jwt.Claims) bool {
		for _, r := range roles {
			if cl.HasRole(r) {
				return true
			}
		}
		return false
	})
}
