package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.DBDriver != "sqlite" || c.DBDSN != "file:./data/keyora.db" ||
		c.AccessTokenTTL != 15*time.Minute || c.PBKDF2Iterations != 600_000 || !c.AutoMigrate || c.AdminKey != "" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestOverrides(t *testing.T) {
	c, err := load(env(map[string]string{
		"KEYORA_ISSUER": "https://id.example.com/", "KEYORA_DB_DRIVER": "postgres", "KEYORA_DB_DSN": "postgres://x",
		"KEYORA_ACCESS_TOKEN_TTL": "5m", "KEYORA_CORS_ALLOWED_ORIGINS": " https://a.test , https://b.test,",
		"KEYORA_TRUST_PROXY_HEADERS": "true", "KEYORA_ADMIN_KEY": strings.Repeat("k", 32),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "https://id.example.com" || c.AccessTokenTTL != 5*time.Minute || len(c.CORSAllowedOrigins) != 2 || !c.TrustProxyHeaders {
		t.Fatalf("overrides not applied: %+v", c)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]map[string]string{
		"KEYORA_ADMIN_KEY":           {"KEYORA_ADMIN_KEY": "short"},
		"KEYORA_ISSUER":              {"KEYORA_ISSUER": "id.example.com"},
		"KEYORA_DB_DRIVER":           {"KEYORA_DB_DRIVER": "oracle"},
		"KEYORA_DB_DSN":              {"KEYORA_DB_DRIVER": "postgres"},
		"KEYORA_PBKDF2_ITERATIONS":   {"KEYORA_PBKDF2_ITERATIONS": "1000"},
		"KEYORA_PASSWORD_MIN_LENGTH": {"KEYORA_PASSWORD_MIN_LENGTH": "4"},
		"KEYORA_RSA_BITS":            {"KEYORA_RSA_BITS": "1024"},
		"KEYORA_ACCESS_TOKEN_TTL":    {"KEYORA_ACCESS_TOKEN_TTL": "soon"},
		"KEYORA_REFRESH_TOKEN_TTL":   {"KEYORA_REFRESH_TOKEN_TTL": "1m"},
		"KEYORA_SMTP_HOST":           {"KEYORA_MAILER": "smtp"},
		"KEYORA_AUTO_MIGRATE":        {"KEYORA_AUTO_MIGRATE": "maybe"},
		"{token}":                    {"KEYORA_PASSWORD_RESET_URL": "https://app.test/reset"},
	}
	for want, vars := range cases {
		if _, err := load(env(vars)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got error %v, want one mentioning %s", vars, err, want)
		}
	}
	// Every problem is reported at once, not one per restart.
	_, err := load(env(map[string]string{"KEYORA_ADMIN_KEY": "short", "KEYORA_RSA_BITS": "512"}))
	if err == nil || strings.Count(err.Error(), "\n") < 1 {
		t.Fatalf("expected multiple errors, got %v", err)
	}
}
