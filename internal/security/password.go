package security

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

const (
	// DefaultPBKDF2Iterations follows the OWASP recommendation for PBKDF2-HMAC-SHA256.
	DefaultPBKDF2Iterations = 600_000
	// MaxPasswordBytes bounds hashing work per request.
	MaxPasswordBytes = 256

	pbkdf2Scheme  = "pbkdf2-sha256"
	pbkdf2SaltLen = 16
	pbkdf2KeyLen  = 32
)

// PasswordHasher derives and verifies password hashes with PBKDF2-HMAC-SHA256,
// the strongest password KDF in the Go standard library. Hashes are
// self-describing ("pbkdf2-sha256$i=600000$salt$hash") so the work factor can
// be raised later and old hashes upgraded on the next successful login.
type PasswordHasher struct {
	Iterations int
}

func (h PasswordHasher) iterations() int {
	if h.Iterations > 0 {
		return h.Iterations
	}
	return DefaultPBKDF2Iterations
}

// Hash returns an encoded hash with a fresh random salt.
func (h PasswordHasher) Hash(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", errors.New("security: password too long")
	}
	salt := RandomBytes(pbkdf2SaltLen)
	key, err := pbkdf2.Key(sha256.New, password, salt, h.iterations(), pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return pbkdf2Scheme + "$i=" + strconv.Itoa(h.iterations()) + "$" +
		enc.EncodeToString(salt) + "$" + enc.EncodeToString(key), nil
}

// Verify reports whether the password matches. needsRehash is true when the
// stored hash used fewer iterations than currently configured.
func (h PasswordHasher) Verify(password, encoded string) (ok, needsRehash bool) {
	if len(password) > MaxPasswordBytes {
		return false, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != pbkdf2Scheme || !strings.HasPrefix(parts[1], "i=") {
		return false, false
	}
	iter, err := strconv.Atoi(parts[1][2:])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false, false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false, false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, iter < h.iterations()
}
