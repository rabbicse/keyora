package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rabbicse/keyora/internal/config"
	"github.com/rabbicse/keyora/internal/server"
)

const testAdminKey = "integration-admin-key-0123456789abcdef"

type instance struct {
	t      *testing.T
	base   string
	cancel context.CancelFunc
	done   chan error
}

// start boots the real server (config -> store -> migrations -> HTTP) on a free port.
func start(t *testing.T, dir string, env map[string]string, exts ...server.Extension) *instance {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	vars := map[string]string{
		"KEYORA_HTTP_ADDR": addr, "KEYORA_ISSUER": "https://id.keyora.test", "KEYORA_ADMIN_KEY": testAdminKey,
		"KEYORA_DB_DRIVER": "sqlite", "KEYORA_DB_DSN": "file:" + filepath.Join(dir, "keyora.db"),
		"KEYORA_KEYS_DIR": filepath.Join(dir, "keys"), "KEYORA_RSA_BITS": "2048", "KEYORA_PBKDF2_ITERATIONS": "100000",
		"KEYORA_SHUTDOWN_TIMEOUT": "5s",
	}
	for k, v := range env {
		vars[k] = v
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	in := &instance{t: t, base: "http://" + addr, cancel: cancel, done: make(chan error, 1)}
	go func() {
		in.done <- server.Run(ctx, cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), exts...)
	}()
	for i := 0; i < 100; i++ {
		if res, err := http.Get(in.base + "/readyz"); err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return in
			}
		}
		select {
		case err := <-in.done:
			t.Fatalf("server exited during startup: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("server did not become ready")
	return nil
}

func (in *instance) stop() {
	in.t.Helper()
	in.cancel()
	select {
	case err := <-in.done:
		if err != nil {
			in.t.Fatalf("shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		in.t.Fatal("server did not shut down")
	}
}

func (in *instance) call(method, path, auth string, body any) (int, map[string]any) {
	in.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, in.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id, secret, ok := strings.Cut(auth, ":"); ok {
		req.SetBasicAuth(id, secret)
	} else if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		in.t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Data map[string]any `json:"data"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out.Data
}

// TestServerLifecycle runs the real process wiring against SQLite, restarts
// it, and checks that data, sessions and signing keys all survive.
func TestServerLifecycle(t *testing.T) {
	dir := t.TempDir()
	in := start(t, dir, nil)

	status, tenant := in.call("POST", "/api/v1/tenants", testAdminKey, map[string]any{"slug": "acme", "name": "Acme"})
	if status != 201 {
		t.Fatalf("create tenant: %d", status)
	}
	tid := tenant["id"].(string)
	_, app := in.call("POST", "/api/v1/tenants/"+tid+"/applications", testAdminKey, map[string]any{"name": "web"})
	client := fmt.Sprint(app["client_id"], ":", app["client_secret"])
	creds := map[string]any{"email": "ada@example.com", "password": "correct horse battery"}
	if status, _ := in.call("POST", "/api/v1/auth/register", client, creds); status != 201 {
		t.Fatalf("register: %d", status)
	}
	status, login := in.call("POST", "/api/v1/auth/login", client, creds)
	if status != 200 {
		t.Fatalf("login: %d", status)
	}
	access, refresh := login["access_token"].(string), login["refresh_token"].(string)

	if info, err := os.Stat(filepath.Join(dir, "keyora.db")); err != nil || info.Size() == 0 {
		t.Fatalf("database file not created: %v", err)
	}
	keys, _ := filepath.Glob(filepath.Join(dir, "keys", "*.pem"))
	if len(keys) != 1 {
		t.Fatalf("expected one generated signing key, found %d", len(keys))
	}
	in.stop()

	// Second boot: same database and keys, no admin key, schema already current.
	in = start(t, dir, map[string]string{"KEYORA_ADMIN_KEY": ""})
	defer in.stop()
	if again, _ := filepath.Glob(filepath.Join(dir, "keys", "*.pem")); len(again) != 1 {
		t.Fatal("a second signing key was generated on restart")
	}
	if status, me := in.call("GET", "/api/v1/users/me", access, nil); status != 200 || me["email"] != "ada@example.com" {
		t.Fatalf("access token issued before the restart was rejected after it: %d %v", status, me)
	}
	if status, _ := in.call("POST", "/api/v1/auth/refresh", client, map[string]any{"refresh_token": refresh}); status != 200 {
		t.Fatalf("session did not survive the restart: %d", status)
	}
	if status, _ := in.call("POST", "/api/v1/auth/refresh", client, map[string]any{"refresh_token": refresh}); status != 401 {
		t.Fatalf("refresh token reuse not detected on SQLite: %d", status)
	}
	if status, _ := in.call("GET", "/api/v1/tenants", testAdminKey, nil); status != 401 {
		t.Fatalf("root API reachable without a configured admin key: %d", status)
	}
}

func TestCLI(t *testing.T) {
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := server.Main(args, "1.2.3", &out, &errOut)
		return code, out.String() + errOut.String()
	}
	if code, out := run("version"); code != 0 || strings.TrimSpace(out) != "1.2.3" {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, out := run("help"); code != 0 || !strings.Contains(out, "migrate") {
		t.Fatalf("help: %d %q", code, out)
	}
	if code, _ := run("frobnicate"); code != 2 {
		t.Fatalf("unknown command exit code %d", code)
	}
	t.Setenv("KEYORA_ADMIN_KEY", "short")
	if code, out := run("serve"); code != 2 || !strings.Contains(out, "KEYORA_ADMIN_KEY") {
		t.Fatalf("invalid configuration: %d %q", code, out)
	}
	t.Setenv("KEYORA_ADMIN_KEY", "")

	dir := t.TempDir()
	t.Setenv("KEYORA_DB_DSN", "file:"+filepath.Join(dir, "cli.db"))
	t.Setenv("KEYORA_KEYS_DIR", filepath.Join(dir, "keys"))
	t.Setenv("KEYORA_RSA_BITS", "2048")
	if code, out := run("migrate"); code != 0 || !strings.Contains(out, "0001_init") {
		t.Fatalf("migrate: %d %q", code, out)
	}
	if code, out := run("migrate"); code != 0 || !strings.Contains(out, "up to date") {
		t.Fatalf("second migrate: %d %q", code, out)
	}
	if code, out := run("keygen"); code != 0 || !strings.Contains(out, "kid") {
		t.Fatalf("keygen: %d %q", code, out)
	}
	if code, _ := run("healthcheck", "-url", "http://127.0.0.1:1/readyz"); code != 1 {
		t.Fatalf("healthcheck against a dead port returned %d", code)
	}
}
