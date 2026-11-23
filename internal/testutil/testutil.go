// Package testutil holds helpers shared by Keyora's tests.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/rabbicse/keyora/internal/mailer"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
	"github.com/rabbicse/keyora/internal/store"
)

var (
	keyOnce sync.Once
	keyRing *security.KeyRing
)

// KeyRing returns a process-wide 2048-bit test key ring (generated once).
func KeyRing(t testing.TB) *security.KeyRing {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keyRing, err = security.NewKeyRing(&security.Key{ID: "test-key", Private: k})
		if err != nil {
			panic(err)
		}
	})
	return keyRing
}

// Clock is a manually advanced time source.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func NewClock() *Clock { return &Clock{now: time.Now().UTC().Truncate(time.Second)} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Logger discards output.
func Logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Env is a service wired for tests with fast hashing and synchronous mail.
type Env struct {
	Svc   *service.Service
	Store store.Store
	Mail  *mailer.Recorder
	Clock *Clock
}

// NewEnv builds a service on the given store. opt overrides are optional.
func NewEnv(t testing.TB, st store.Store, mod func(*service.Options)) *Env {
	t.Helper()
	clock := NewClock()
	mail := &mailer.Recorder{}
	opt := service.Options{
		Issuer: "https://id.test", PBKDF2Iterations: 1000, MaxFailedLogins: 3,
		LockoutDuration: 10 * time.Minute, SynchronousMail: true, Clock: clock.Now,
	}
	if mod != nil {
		mod(&opt)
	}
	svc, err := service.New(st, KeyRing(t), mail, opt, Logger())
	if err != nil {
		t.Fatal(err)
	}
	return &Env{Svc: svc, Store: st, Mail: mail, Clock: clock}
}
