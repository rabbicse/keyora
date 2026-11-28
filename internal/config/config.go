// Package config loads Keyora's configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr          string
	Issuer            string
	DBDriver          string
	DBDSN             string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	DBPgBouncer       bool
	AutoMigrate       bool
	KeysDir           string
	RSABits           int
	AdminKey          string

	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	PasswordMinLength        int
	PBKDF2Iterations         int
	MaxFailedLogins          int
	LockoutDuration          time.Duration
	RequireEmailVerification bool
	EmailVerificationURL     string
	PasswordResetURL         string

	// LegacyTutorialClientID enables the tutorial-compatibility API when set.
	LegacyTutorialAPI      bool
	LegacyTutorialClientID string

	RateLimitPerMinute int
	RateLimitBurst     int
	TrustProxyHeaders  bool
	CORSAllowedOrigins []string

	Mailer       string
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	// GraphQLEnabled serves the GraphQL API at POST /graphql on the HTTP
	// listener, in binaries that link the GraphQL transport.
	GraphQLEnabled bool
	// GraphQLIntrospection lets clients query the schema itself.
	GraphQLIntrospection bool
	// GRPCAddr is the listen address of the gRPC API, in binaries that link
	// the gRPC transport. Empty disables it.
	GRPCAddr       string
	GRPCReflection bool

	LogLevel        string
	LogFormat       string
	MetricsEnabled  bool
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) { return load(os.Getenv) }

func load(get func(string) string) (*Config, error) {
	l := &loader{get: get}
	c := &Config{
		HTTPAddr:          l.str("KEYORA_HTTP_ADDR", ":8080"),
		Issuer:            strings.TrimRight(l.str("KEYORA_ISSUER", "http://localhost:8080"), "/"),
		DBDriver:          l.str("KEYORA_DB_DRIVER", "sqlite"),
		DBDSN:             l.str("KEYORA_DB_DSN", ""),
		DBMaxOpenConns:    l.int("KEYORA_DB_MAX_OPEN_CONNS", 20),
		DBMaxIdleConns:    l.int("KEYORA_DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime: l.dur("KEYORA_DB_CONN_MAX_LIFETIME", 30*time.Minute),
		DBPgBouncer:       l.bool("KEYORA_DB_PGBOUNCER", false),
		AutoMigrate:       l.bool("KEYORA_AUTO_MIGRATE", true),
		KeysDir:           l.str("KEYORA_KEYS_DIR", "./data/keys"),
		RSABits:           l.int("KEYORA_RSA_BITS", 3072),
		AdminKey:          l.str("KEYORA_ADMIN_KEY", ""),

		AccessTokenTTL:           l.dur("KEYORA_ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:          l.dur("KEYORA_REFRESH_TOKEN_TTL", 30*24*time.Hour),
		PasswordMinLength:        l.int("KEYORA_PASSWORD_MIN_LENGTH", 8),
		PBKDF2Iterations:         l.int("KEYORA_PBKDF2_ITERATIONS", 600_000),
		MaxFailedLogins:          l.int("KEYORA_MAX_FAILED_LOGINS", 5),
		LockoutDuration:          l.dur("KEYORA_LOCKOUT_DURATION", 15*time.Minute),
		RequireEmailVerification: l.bool("KEYORA_REQUIRE_EMAIL_VERIFICATION", false),
		EmailVerificationURL:     l.str("KEYORA_EMAIL_VERIFICATION_URL", ""),
		PasswordResetURL:         l.str("KEYORA_PASSWORD_RESET_URL", ""),

		LegacyTutorialAPI:      l.bool("KEYORA_LEGACY_TUTORIAL_API", false),
		LegacyTutorialClientID: l.str("KEYORA_LEGACY_TUTORIAL_CLIENT_ID", ""),

		RateLimitPerMinute: l.int("KEYORA_RATE_LIMIT_PER_MINUTE", 60),
		RateLimitBurst:     l.int("KEYORA_RATE_LIMIT_BURST", 20),
		TrustProxyHeaders:  l.bool("KEYORA_TRUST_PROXY_HEADERS", false),
		CORSAllowedOrigins: l.list("KEYORA_CORS_ALLOWED_ORIGINS"),

		Mailer:       l.str("KEYORA_MAILER", "log"),
		SMTPHost:     l.str("KEYORA_SMTP_HOST", ""),
		SMTPPort:     l.str("KEYORA_SMTP_PORT", "587"),
		SMTPUsername: l.str("KEYORA_SMTP_USERNAME", ""),
		SMTPPassword: l.str("KEYORA_SMTP_PASSWORD", ""),
		SMTPFrom:     l.str("KEYORA_SMTP_FROM", ""),

		GraphQLEnabled:       l.bool("KEYORA_GRAPHQL_ENABLED", true),
		GraphQLIntrospection: l.bool("KEYORA_GRAPHQL_INTROSPECTION", true),
		GRPCAddr:             l.str("KEYORA_GRPC_ADDR", ""),
		GRPCReflection:       l.bool("KEYORA_GRPC_REFLECTION", true),

		LogLevel:        l.str("KEYORA_LOG_LEVEL", "info"),
		LogFormat:       l.str("KEYORA_LOG_FORMAT", "json"),
		MetricsEnabled:  l.bool("KEYORA_METRICS_ENABLED", true),
		ReadTimeout:     l.dur("KEYORA_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:    l.dur("KEYORA_HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:     l.dur("KEYORA_HTTP_IDLE_TIMEOUT", 120*time.Second),
		ShutdownTimeout: l.dur("KEYORA_SHUTDOWN_TIMEOUT", 20*time.Second),
	}
	if c.DBDSN == "" && c.DBDriver == "sqlite" {
		c.DBDSN = "file:./data/keyora.db"
	}
	l.errs = append(l.errs, c.validate()...)
	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return c, nil
}

func (c *Config) validate() []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if u, err := url.Parse(c.Issuer); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		bad("KEYORA_ISSUER must be an absolute http(s) URL")
	}
	switch c.DBDriver {
	case "memory", "sqlite":
	case "postgres":
		if c.DBDSN == "" {
			bad("KEYORA_DB_DSN is required when KEYORA_DB_DRIVER=postgres")
		}
	default:
		bad("KEYORA_DB_DRIVER must be one of memory, sqlite, postgres")
	}
	if c.AdminKey != "" && len(c.AdminKey) < 32 {
		bad("KEYORA_ADMIN_KEY must be at least 32 characters")
	}
	if c.RSABits < 2048 {
		bad("KEYORA_RSA_BITS must be at least 2048")
	}
	if c.AccessTokenTTL < time.Minute || c.AccessTokenTTL > 24*time.Hour {
		bad("KEYORA_ACCESS_TOKEN_TTL must be between 1m and 24h")
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		bad("KEYORA_REFRESH_TOKEN_TTL must be longer than the access token TTL")
	}
	if c.PasswordMinLength < 8 {
		bad("KEYORA_PASSWORD_MIN_LENGTH must be at least 8")
	}
	if c.PBKDF2Iterations < 100_000 {
		bad("KEYORA_PBKDF2_ITERATIONS must be at least 100000")
	}
	if c.MaxFailedLogins < 1 {
		bad("KEYORA_MAX_FAILED_LOGINS must be at least 1")
	}
	if c.LegacyTutorialAPI && c.LegacyTutorialClientID == "" {
		bad("KEYORA_LEGACY_TUTORIAL_CLIENT_ID is required when KEYORA_LEGACY_TUTORIAL_API=true")
	}
	switch c.Mailer {
	case "log":
	case "smtp":
		if c.SMTPHost == "" || c.SMTPFrom == "" {
			bad("KEYORA_SMTP_HOST and KEYORA_SMTP_FROM are required when KEYORA_MAILER=smtp")
		}
	default:
		bad("KEYORA_MAILER must be log or smtp")
	}
	for _, v := range []string{c.EmailVerificationURL, c.PasswordResetURL} {
		if v != "" && !strings.Contains(v, "{token}") {
			bad("email link templates must contain the {token} placeholder")
		}
	}
	return errs
}

type loader struct {
	get  func(string) string
	errs []error
}

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(l.get(key)); v != "" {
		return v
	}
	return def
}

func (l *loader) int(key string, def int) int {
	v := l.str(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be an integer", key))
		return def
	}
	return n
}

func (l *loader) bool(key string, def bool) bool {
	v := l.str(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be true or false", key))
		return def
	}
	return b
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v := l.str(key, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errs = append(l.errs, fmt.Errorf("%s must be a duration such as 15m", key))
		return def
	}
	return d
}

func (l *loader) list(key string) []string {
	var out []string
	for _, v := range strings.Split(l.get(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
