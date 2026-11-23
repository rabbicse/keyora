package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

func TestPasswordHashing(t *testing.T) {
	h := PasswordHasher{Iterations: 1000}
	a, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := h.Hash("correct horse battery staple")
	if a == b {
		t.Fatal("two hashes of the same password are identical: salt is not random")
	}
	if !strings.HasPrefix(a, "pbkdf2-sha256$i=1000$") || strings.Contains(a, "correct") {
		t.Fatalf("unexpected encoding %q", a)
	}
	if ok, rehash := h.Verify("correct horse battery staple", a); !ok || rehash {
		t.Fatalf("ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := h.Verify("correct horse battery stapl", a); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _ := h.Verify("", a); ok {
		t.Fatal("empty password accepted")
	}
	// A stronger configured work factor flags old hashes for upgrade.
	if ok, rehash := (PasswordHasher{Iterations: 5000}).Verify("correct horse battery staple", a); !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v, want true,true", ok, rehash)
	}
	if _, err := h.Hash(strings.Repeat("x", MaxPasswordBytes+1)); err == nil {
		t.Fatal("oversized password hashed")
	}
	if ok, _ := h.Verify(strings.Repeat("x", MaxPasswordBytes+1), a); ok {
		t.Fatal("oversized password verified")
	}
}

func TestDefaultIterationsMeetOWASP(t *testing.T) {
	if (PasswordHasher{}).iterations() < 600_000 {
		t.Fatal("default PBKDF2-SHA256 work factor is below the OWASP recommendation")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	h := PasswordHasher{Iterations: 1000}
	for _, enc := range []string{"", "plaintext", "$$$", "pbkdf2-sha256$i=0$AA$AA", "pbkdf2-sha256$i=-5$AA$AA",
		"pbkdf2-sha256$i=99999999999$AA$AA", "pbkdf2-sha256$i=1000$!!$AA", "pbkdf2-sha256$i=1000$AA$", "bcrypt$i=1000$AA$AA",
		"pbkdf2-sha256$1000$AA$AA", "pbkdf2-sha256$i=1000$AA$AA$extra"} {
		if ok, _ := h.Verify("pw", enc); ok {
			t.Fatalf("malformed hash %q verified", enc)
		}
	}
}

func FuzzPasswordVerify(f *testing.F) {
	h := PasswordHasher{Iterations: 10}
	good, _ := h.Hash("secret-password")
	f.Add("secret-password", good)
	f.Add("x", "pbkdf2-sha256$i=10$AA$AA")
	f.Add("", "$$$")
	f.Fuzz(func(t *testing.T, password, encoded string) {
		if len(encoded) > 4096 {
			return
		}
		// Keep the fuzzer from asking for enormous work factors.
		if i := strings.Index(encoded, "i="); i >= 0 && len(encoded) > i+6 {
			return
		}
		h.Verify(password, encoded) // must not panic
	})
}

func TestRandomness(t *testing.T) {
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, tok := NewID(), NewToken("kyr_")
		if !uuid.MatchString(id) {
			t.Fatalf("not a v4 UUID: %s", id)
		}
		if len(tok) != 4+43 || seen[id] || seen[tok] {
			t.Fatalf("bad or repeated value: %s %s", id, tok)
		}
		seen[id], seen[tok] = true, true
	}
	if HashToken("a") == HashToken("b") || len(HashToken("a")) != 64 {
		t.Fatal("HashToken is not SHA-256 hex")
	}
	if !ConstantTimeEqual("abc", "abc") || ConstantTimeEqual("abc", "abd") || ConstantTimeEqual("abc", "ab") {
		t.Fatal("ConstantTimeEqual is wrong")
	}
}

func TestKeyRingLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	ring, created, err := LoadOrCreateKeyRing(dir, 2048)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	first := ring.ActiveKeyID()
	info, _ := os.Stat(filepath.Join(dir, first+".pem"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions are %v, want 0600", info.Mode().Perm())
	}
	oldToken, _ := ring.Signer().Sign(jwt.Claims{Subject: "u", ExpiresAt: time.Now().Add(time.Hour).Unix()})

	// Rotation: a newer key becomes active, the old one keeps verifying.
	later := time.Now().Add(time.Hour)
	second, err := GenerateKeyFile(dir, 2048, later)
	if err != nil {
		t.Fatal(err)
	}
	// Same timestamp means the same file name: it must refuse, not overwrite.
	if _, err := GenerateKeyFile(dir, 2048, later); err == nil {
		t.Fatal("an existing key file was overwritten")
	}
	ring, created, err = LoadOrCreateKeyRing(dir, 2048)
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if ring.ActiveKeyID() != second || second <= first {
		t.Fatalf("active=%s, want the newest key %s", ring.ActiveKeyID(), second)
	}
	if len(ring.JWKS().Keys) != 2 {
		t.Fatal("JWKS must publish every loaded key")
	}
	if _, err := jwt.Verify(oldToken, ring.PublicKey, jwt.Validation{}); err != nil {
		t.Fatalf("token signed before rotation no longer verifies: %v", err)
	}
	newToken, _ := ring.Signer().Sign(jwt.Claims{Subject: "u", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := jwt.Verify(newToken, ring.JWKS().KeyFunc(), jwt.Validation{}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyLoadingRejectsBadInput(t *testing.T) {
	if _, err := GenerateKeyFile(t.TempDir(), 1024, time.Now()); err == nil {
		t.Fatal("generated a 1024-bit key")
	}
	if _, err := LoadKeyRing(t.TempDir()); err == nil {
		t.Fatal("empty directory produced a key ring")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "junk.pem"), []byte("not pem"), 0o600)
	if _, err := LoadKeyRing(dir); err == nil {
		t.Fatal("junk file loaded")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "weak.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}), 0o600)
	if _, err := LoadKeyRing(dir); err == nil {
		t.Fatal("1024-bit key loaded")
	}
	// PKCS#1 files written by the original tutorial's keygen still load.
	legacy, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "2026-02-07T17-33-16.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(legacy)}), 0o600)
	ring, err := LoadKeyRing(dir)
	if err != nil || ring.ActiveKeyID() != "2026-02-07T17-33-16" {
		t.Fatalf("legacy PKCS#1 key not loaded: %v", err)
	}
}
