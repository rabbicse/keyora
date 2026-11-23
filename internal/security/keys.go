package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rabbicse/keyora/jwt"
)

// MinRSABits is the smallest signing key Keyora will load or generate.
const MinRSABits = 2048

// Key is one RSA signing key. Its ID is published as the JWT "kid".
type Key struct {
	ID      string
	Private *rsa.PrivateKey
}

// KeyRing holds every loaded signing key. The key with the lexicographically
// greatest ID signs new tokens; all keys stay published in the JWKS so tokens
// signed before a rotation keep verifying until they expire.
type KeyRing struct {
	keys   map[string]*Key
	active *Key
}

func NewKeyRing(keys ...*Key) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, errors.New("security: no signing keys")
	}
	r := &KeyRing{keys: make(map[string]*Key, len(keys))}
	for _, k := range keys {
		if k.Private.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("security: key %q is shorter than %d bits", k.ID, MinRSABits)
		}
		r.keys[k.ID] = k
		if r.active == nil || k.ID > r.active.ID {
			r.active = k
		}
	}
	return r, nil
}

// Signer returns a signer for the active key.
func (r *KeyRing) Signer() jwt.Signer {
	return jwt.Signer{Key: r.active.Private, KeyID: r.active.ID}
}

// ActiveKeyID returns the ID of the key used for new tokens.
func (r *KeyRing) ActiveKeyID() string { return r.active.ID }

// PublicKey resolves a key ID; it satisfies jwt.KeyFunc.
func (r *KeyRing) PublicKey(kid string) (*rsa.PublicKey, bool) {
	k, ok := r.keys[kid]
	if !ok {
		return nil, false
	}
	return &k.Private.PublicKey, true
}

// JWKS returns the public half of every key, in stable order.
func (r *KeyRing) JWKS() jwt.JWKS {
	ids := make([]string, 0, len(r.keys))
	for id := range r.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	set := jwt.JWKS{Keys: make([]jwt.JWK, 0, len(ids))}
	for _, id := range ids {
		set.Keys = append(set.Keys, jwt.PublicJWK(id, &r.keys[id].Private.PublicKey))
	}
	return set
}

// GenerateKeyFile writes a new RSA private key to dir as <timestamp>.pem with
// 0600 permissions and returns its key ID. It never overwrites a file.
func GenerateKeyFile(dir string, bits int, now time.Time) (string, error) {
	if bits < MinRSABits {
		return "", fmt.Errorf("security: RSA keys must be at least %d bits", MinRSABits)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	kid := now.UTC().Format("20060102T150405Z")
	f, err := os.OpenFile(filepath.Join(dir, kid+".pem"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return "", err
	}
	return kid, f.Close()
}

// LoadKeyRing loads every *.pem private key in dir. The file name without
// extension is the key ID. PKCS#8 and PKCS#1 encodings are accepted.
func LoadKeyRing(dir string) (*KeyRing, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	var keys []*Key
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("security: %s is not PEM", file)
		}
		priv, err := parseRSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("security: %s: %w", file, err)
		}
		keys = append(keys, &Key{ID: strings.TrimSuffix(filepath.Base(file), ".pem"), Private: priv})
	}
	return NewKeyRing(keys...)
}

// LoadOrCreateKeyRing loads dir, generating a first key when it holds none.
func LoadOrCreateKeyRing(dir string, bits int) (*KeyRing, bool, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
	created := false
	if len(files) == 0 {
		if _, err := GenerateKeyFile(dir, bits, time.Now()); err != nil {
			return nil, false, err
		}
		created = true
	}
	ring, err := LoadKeyRing(dir)
	return ring, created, err
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not an RSA private key")
	}
	return x509.ParsePKCS1PrivateKey(der)
}
