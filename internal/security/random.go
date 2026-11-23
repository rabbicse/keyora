// Package security contains Keyora's cryptographic building blocks. Everything
// here is standard library only.
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RandomBytes returns n bytes from the OS CSPRNG. crypto/rand never returns a
// short read; on an unrecoverable entropy failure the runtime aborts.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// NewID returns a random RFC 4122 version 4 UUID.
func NewID() string {
	b := RandomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewToken returns prefix + 256 bits of URL-safe randomness.
func NewToken(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(RandomBytes(32))
}

// HashToken returns the hex SHA-256 of a high-entropy token. A fast hash is
// correct here: the input is 256 random bits, so there is nothing to brute
// force, and lookups by hash must be cheap.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking where they differ.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
