// Package server wires configuration, storage, the service and the HTTP API
// into a runnable process. It imports no database driver; see cmd/keyora.
package server

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rabbicse/keyora/api"
	"github.com/rabbicse/keyora/internal/access"
	"github.com/rabbicse/keyora/internal/config"
	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/mailer"
	"github.com/rabbicse/keyora/internal/ratelimit"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/store/sqlstore"
)

// sqlDrivers maps KEYORA_DB_DRIVER to the database/sql driver name the
// binary is expected to have registered, and to the SQL dialect.
var sqlDrivers = map[string][2]string{
	"postgres": {"pgx", sqlstore.DialectPostgres},
	"sqlite":   {"sqlite", sqlstore.DialectSQLite},
}

const usage = `Keyora - one identity, every application.

Usage:
  keyora [command]

Commands:
  serve        Run the server (default)
  migrate      Apply pending database migrations and exit
  keygen       Generate a new signing key in KEYORA_KEYS_DIR and exit
  healthcheck  Probe a running server's /readyz endpoint (for containers)
  version      Print the version

Configuration is read from KEYORA_* environment variables; see .env.example.
`

// Deps is what an Extension is given to work with.
type Deps struct {
	Service *service.Service
	// Gate identifies callers exactly as the REST API does.
	Gate    *access.Gate
	Config  *config.Config
	Log     *slog.Logger
	Version string
}

// Extension links one more transport into a Keyora binary. The core module
// speaks REST with the standard library alone; transports that need
// third-party code (GraphQL, gRPC) live in modules of their own and are
// handed to Main by the binary that wants them.
type Extension struct {
	// Name appears in logs ("graphql", "grpc").
	Name string
	// HTTP returns handlers to mount on the HTTP listener, keyed by ServeMux
	// pattern ("POST /graphql"). They run behind the REST API's middleware.
	// A nil map means the extension is switched off by configuration.
	HTTP func(Deps) (map[string]http.Handler, error)
	// Serve runs a listener of the extension's own until ctx is cancelled,
	// then shuts down gracefully. It returns nil at once when the extension
	// is switched off by configuration.
	Serve func(ctx context.Context, d Deps) error
}

// Main is the entry point shared by every Keyora binary. It returns the
// process exit code.
func Main(args []string, version string, stdout, stderr io.Writer, exts ...Extension) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "healthcheck":
		return healthcheck(args, stderr)
	case "serve", "migrate", "keygen":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "invalid configuration:\n%v\n", err)
		return 2
	}
	log := newLogger(cfg, stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "keygen":
		kid, err := security.GenerateKeyFile(cfg.KeysDir, cfg.RSABits, time.Now())
		if err != nil {
			log.Error("key generation failed", "error", err)
			return 1
		}
		log.Info("signing key generated; restart Keyora to start signing with it", "kid", kid, "dir", cfg.KeysDir)
		return 0
	case "migrate":
		st, err := openStore(ctx, cfg, log, true)
		if err != nil {
			log.Error("migration failed", "error", err)
			return 1
		}
		st.Close()
		return 0
	}
	if err := Run(ctx, cfg, version, log, exts...); err != nil {
		log.Error("server stopped with error", "error", err)
		return 1
	}
	return 0
}

func newLogger(cfg *config.Config, w io.Writer) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// sqliteDSN adds the pragmas Keyora relies on: enforced foreign keys, WAL,
// a busy timeout, and immediate write transactions to avoid lock upgrades.
func sqliteDSN(dsn string) string {
	if strings.Contains(dsn, "_pragma=") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
}

// PgBouncerDSN makes a PostgreSQL DSN safe for PgBouncer in transaction (or
// statement) pooling mode by turning off named prepared statements, which
// belong to one server connection and cannot be relied on when the pooler may
// hand each transaction a different one. Queries are still sent with bound
// parameters, never interpolated. A DSN that already chooses a mode is left alone.
func PgBouncerDSN(dsn string) string {
	if strings.Contains(dsn, "default_query_exec_mode") {
		return dsn
	}
	const opt = "default_query_exec_mode=exec"
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if strings.Contains(dsn, "?") {
			return dsn + "&" + opt
		}
		return dsn + "?" + opt
	}
	return dsn + " " + opt // keyword/value form
}

func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger, forceMigrate bool) (store.Store, error) {
	if cfg.DBDriver == "memory" {
		log.Warn("using the in-memory store: all data is lost on exit; not for production")
		return memory.New(), nil
	}
	drv := sqlDrivers[cfg.DBDriver]
	dsn := cfg.DBDSN
	if cfg.DBDriver == "sqlite" {
		if path, ok := strings.CutPrefix(strings.SplitN(dsn, "?", 2)[0], "file:"); ok && !strings.Contains(dsn, "memory") {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return nil, err
			}
		}
		dsn = sqliteDSN(dsn)
	}
	if cfg.DBDriver == "postgres" && cfg.DBPgBouncer {
		dsn = PgBouncerDSN(dsn)
		log.Info("PostgreSQL through a connection pooler: server-side prepared statements are disabled")
	}
	db, err := sql.Open(drv[0], dsn)
	if err != nil {
		return nil, fmt.Errorf("open database (is the %q driver compiled into this binary?): %w", drv[0], err)
	}
	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(cfg.DBConnMaxLifetime)
	if strings.Contains(dsn, "memory") {
		db.SetMaxOpenConns(1) // each SQLite in-memory connection is its own database
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	st, err := sqlstore.New(db, drv[1])
	if err != nil {
		db.Close()
		return nil, err
	}
	if cfg.AutoMigrate || forceMigrate {
		applied, err := st.Migrate(ctx)
		if err != nil {
			db.Close()
			return nil, err
		}
		if len(applied) > 0 {
			log.Info("database migrations applied", "versions", applied)
		} else {
			log.Info("database schema is up to date")
		}
	}
	return st, nil
}

// Run starts the server and blocks until ctx is cancelled, then shuts down gracefully.
func Run(ctx context.Context, cfg *config.Config, version string, log *slog.Logger, exts ...Extension) error {
	st, err := openStore(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()

	keys, created, err := security.LoadOrCreateKeyRing(cfg.KeysDir, cfg.RSABits)
	if err != nil {
		return fmt.Errorf("load signing keys from %s: %w", cfg.KeysDir, err)
	}
	if created {
		log.Info("generated the first signing key", "dir", cfg.KeysDir, "kid", keys.ActiveKeyID())
	}

	var mail mailer.Mailer = mailer.Log{Logger: log}
	if cfg.Mailer == "smtp" {
		mail = mailer.SMTP{Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword, From: cfg.SMTPFrom}
	} else {
		log.Warn("using the log mailer: verification and reset tokens are written to the log; set KEYORA_MAILER=smtp in production")
	}

	svc, err := service.New(st, keys, mail, service.Options{
		Issuer: cfg.Issuer, AccessTokenTTL: cfg.AccessTokenTTL, RefreshTokenTTL: cfg.RefreshTokenTTL,
		PasswordMinLength: cfg.PasswordMinLength, PBKDF2Iterations: cfg.PBKDF2Iterations,
		MaxFailedLogins: cfg.MaxFailedLogins, LockoutDuration: cfg.LockoutDuration,
		RequireEmailVerification: cfg.RequireEmailVerification,
		EmailVerificationURL:     cfg.EmailVerificationURL, PasswordResetURL: cfg.PasswordResetURL,
	}, log)
	if err != nil {
		return err
	}
	if cfg.AdminKey == "" {
		log.Warn("KEYORA_ADMIN_KEY is not set: tenants cannot be created through the API")
	}

	legacyClient := ""
	if cfg.LegacyTutorialAPI {
		legacyClient = cfg.LegacyTutorialClientID
		log.Warn("the tutorial-compatibility API is enabled: its challenge-response login stores password-equivalent verifiers; use it for migration only",
			"client_id", legacyClient)
	}
	handler := httpapi.New(svc, httpapi.Config{
		AdminKey: cfg.AdminKey, TrustProxyHeaders: cfg.TrustProxyHeaders, CORSAllowedOrigins: cfg.CORSAllowedOrigins,
		Limiter: ratelimit.New(cfg.RateLimitPerMinute, cfg.RateLimitBurst), MetricsEnabled: cfg.MetricsEnabled,
		HSTS: strings.HasPrefix(cfg.Issuer, "https://"), Version: version, OpenAPI: api.OpenAPI,
		LegacyClientID: legacyClient,
	}, log)

	// Extensions stop when the HTTP server does, whichever fails first.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	deps := Deps{Service: svc, Gate: handler.Gate(), Config: cfg, Log: log, Version: version}
	linked := map[string]bool{}
	for _, ext := range exts {
		linked[ext.Name] = true
		if ext.HTTP == nil {
			continue
		}
		routes, err := ext.HTTP(deps)
		if err != nil {
			return fmt.Errorf("%s: %w", ext.Name, err)
		}
		for pattern, h := range routes {
			handler.Mount(pattern, h)
			log.Info("transport mounted", "transport", ext.Name, "route", pattern)
		}
	}
	if cfg.GRPCAddr != "" && !linked["grpc"] {
		log.Warn("KEYORA_GRPC_ADDR is set but this binary was built without the gRPC transport")
	}

	srv := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadTimeout: cfg.ReadTimeout, ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return err
	}

	go purgeLoop(ctx, svc, log)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("keyora is listening", "addr", ln.Addr().String(), "issuer", cfg.Issuer, "db", cfg.DBDriver, "version", version)

	var extWG sync.WaitGroup
	extErr := make(chan error, len(exts))
	for _, ext := range exts {
		if ext.Serve == nil {
			continue
		}
		extWG.Add(1)
		go func() {
			defer extWG.Done()
			if err := ext.Serve(ctx, deps); err != nil {
				extErr <- fmt.Errorf("%s: %w", ext.Name, err)
			}
		}()
	}

	var failure error
	select {
	case err := <-errc:
		return err
	case failure = <-extErr:
		log.Error("a transport failed; shutting down", "error", failure)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	cancel()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	extWG.Wait()
	log.Info("stopped")
	return failure
}

func purgeLoop(ctx context.Context, svc *service.Service, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := svc.PurgeExpired(ctx); err != nil {
				log.Error("purging expired records failed", "error", err)
			} else if n > 0 {
				log.Info("purged expired records", "count", n)
			}
		}
	}
}

func healthcheck(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "readiness URL (default http://127.0.0.1:<port>/readyz)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := *url
	if target == "" {
		addr := os.Getenv("KEYORA_HTTP_ADDR")
		if addr == "" {
			addr = ":8080"
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			port = "8080"
		}
		target = "http://127.0.0.1:" + port + "/readyz"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "unhealthy: status", resp.StatusCode)
		return 1
	}
	return 0
}
