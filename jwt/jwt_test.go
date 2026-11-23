package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	testKey, _  = rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	now         = time.Unix(1_900_000_000, 0)
)

func keys(kid string) (*rsa.PublicKey, bool) {
	if kid == "k1" {
		return &testKey.PublicKey, true
	}
	return nil, false
}

func valid() Claims {
	return Claims{Issuer: "https://id.test", Subject: "user-1", Audience: Audience{"app-1"},
		ExpiresAt: now.Add(time.Hour).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
		TenantID: "t1", Roles: []string{"editor"}, Permissions: []string{"orders:read"}}
}

func sign(t testing.TB, c Claims) string {
	t.Helper()
	tok, err := Signer{Key: testKey, KeyID: "k1"}.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func check() Validation {
	return Validation{Issuer: "https://id.test", Audience: "app-1", Now: func() time.Time { return now }}
}

// forge builds a token with an arbitrary header and signature.
func forge(header map[string]any, c Claims, sign func(input string) []byte) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(c)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return input + "." + b64.EncodeToString(sign(input))
}

func rs256(key *rsa.PrivateKey) func(string) []byte {
	return func(input string) []byte {
		sum := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
		return sig
	}
}

func TestRoundTrip(t *testing.T) {
	got, err := Verify(sign(t, valid()), keys, check())
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "user-1" || got.TenantID != "t1" || !got.HasRole("editor") || !got.HasPermission("orders:read") || got.HasPermission("x") {
		t.Fatalf("claims not preserved: %+v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	good := sign(t, valid())
	parts := strings.Split(good, ".")
	with := func(mod func(*Claims)) string { c := valid(); mod(&c); return sign(t, c) }

	// Classic algorithm confusion: an HS256 token keyed with the RSA public key.
	pubDER, _ := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	hs256 := forge(map[string]any{"alg": "HS256", "kid": "k1"}, valid(), func(in string) []byte {
		m := hmac.New(sha256.New, pubDER)
		m.Write([]byte(in))
		return m.Sum(nil)
	})
	sigBytes, _ := b64.DecodeString(parts[2])
	shortSig := parts[0] + "." + parts[1] + "." + b64.EncodeToString(sigBytes[:len(sigBytes)-3])
	flipped := append([]byte{}, sigBytes...)
	flipped[len(flipped)/2] ^= 0x01
	bitFlip := parts[0] + "." + parts[1] + "." + b64.EncodeToString(flipped)
	tamperedPayload, _ := json.Marshal(func() Claims { c := valid(); c.Subject = "admin"; return c }())

	cases := []struct {
		name  string
		token string
		v     Validation
		want  error
	}{
		{"alg none", forge(map[string]any{"alg": "none", "kid": "k1"}, valid(), func(string) []byte { return []byte("x") }), check(), ErrAlgorithm},
		{"alg none empty signature", strings.TrimRight(forge(map[string]any{"alg": "none", "kid": "k1"}, valid(), func(string) []byte { return nil }), "."), check(), ErrMalformed},
		{"alg HS256 confusion", hs256, check(), ErrAlgorithm},
		{"alg RS512", forge(map[string]any{"alg": "RS512", "kid": "k1"}, valid(), rs256(testKey)), check(), ErrAlgorithm},
		{"alg lowercase", forge(map[string]any{"alg": "rs256", "kid": "k1"}, valid(), rs256(testKey)), check(), ErrAlgorithm},
		{"signed by another key", forge(map[string]any{"alg": "RS256", "kid": "k1"}, valid(), rs256(otherKey)), check(), ErrSignature},
		{"unknown kid", forge(map[string]any{"alg": "RS256", "kid": "k2"}, valid(), rs256(testKey)), check(), ErrUnknownKey},
		{"missing kid", forge(map[string]any{"alg": "RS256"}, valid(), rs256(testKey)), check(), ErrUnknownKey},
		{"tampered payload", parts[0] + "." + b64.EncodeToString(tamperedPayload) + "." + parts[2], check(), ErrSignature},
		{"short signature", shortSig, check(), ErrSignature},
		{"one bit flipped in signature", bitFlip, check(), ErrSignature},
		{"clipped token", good[:len(good)-4], check(), ErrMalformed},
		{"expired", with(func(c *Claims) { c.ExpiresAt = now.Add(-time.Second).Unix() }), check(), ErrExpired},
		{"expires exactly now", with(func(c *Claims) { c.ExpiresAt = now.Unix() }), check(), ErrExpired},
		{"no expiry", with(func(c *Claims) { c.ExpiresAt = 0 }), check(), ErrExpired},
		{"not yet valid", with(func(c *Claims) { c.NotBefore = now.Add(time.Minute).Unix() }), check(), ErrNotYetValid},
		{"wrong issuer", with(func(c *Claims) { c.Issuer = "https://evil.test" }), check(), ErrIssuer},
		{"wrong audience", with(func(c *Claims) { c.Audience = Audience{"other-app"} }), check(), ErrAudience},
		{"no audience", with(func(c *Claims) { c.Audience = nil }), check(), ErrAudience},
		{"two segments", parts[0] + "." + parts[1], check(), ErrMalformed},
		{"four segments", good + ".x", check(), ErrMalformed},
		{"empty", "", check(), ErrMalformed},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2], check(), ErrMalformed},
		{"header not json", b64.EncodeToString([]byte("nope")) + "." + parts[1] + "." + parts[2], check(), ErrMalformed},
		{"oversized", good + strings.Repeat("A", MaxTokenBytes), check(), ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Verify(tc.token, keys, tc.v)
			if !errors.Is(err, tc.want) || c != nil {
				t.Fatalf("got claims=%v err=%v, want %v", c, err, tc.want)
			}
		})
	}
}

func TestLeewayAndOptionalChecks(t *testing.T) {
	c := valid()
	c.ExpiresAt = now.Add(-10 * time.Second).Unix()
	v := check()
	v.Leeway = 30 * time.Second
	if _, err := Verify(sign(t, c), keys, v); err != nil {
		t.Fatalf("leeway not applied: %v", err)
	}
	// Empty issuer/audience skip those checks but never the signature or expiry.
	if _, err := Verify(sign(t, valid()), keys, Validation{Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
}

func TestAudienceEncoding(t *testing.T) {
	one, _ := json.Marshal(Audience{"a"})
	many, _ := json.Marshal(Audience{"a", "b"})
	if string(one) != `"a"` || string(many) != `["a","b"]` {
		t.Fatalf("got %s and %s", one, many)
	}
	var a Audience
	if err := json.Unmarshal([]byte(`["x","y"]`), &a); err != nil || !a.Contains("y") {
		t.Fatalf("array audience: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`42`), &a); err == nil {
		t.Fatal("numeric audience accepted")
	}
}

func TestJWKS(t *testing.T) {
	set := JWKS{Keys: []JWK{PublicJWK("k1", &testKey.PublicKey)}}
	raw, _ := json.Marshal(set)
	var decoded JWKS
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sign(t, valid()), decoded.KeyFunc(), check()); err != nil {
		t.Fatalf("token did not verify through JWKS round trip: %v", err)
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Fatal("JWKS leaks private key material")
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := PublicJWK("w", &weak.PublicKey).RSAPublicKey(); err == nil {
		t.Fatal("1024-bit key accepted")
	}
	for _, bad := range []JWK{{Kty: "EC", N: "AQAB", E: "AQAB"}, {Kty: "RSA", N: "!!", E: "AQAB"}, {Kty: "RSA", N: set.Keys[0].N, E: ""}, {Kty: "RSA", N: set.Keys[0].N, E: "Ag"}} {
		if _, err := bad.RSAPublicKey(); err == nil {
			t.Fatalf("invalid JWK accepted: %+v", bad)
		}
	}
	enc := JWK{Kty: "RSA", Use: "enc", Kid: "e1", N: set.Keys[0].N, E: set.Keys[0].E}
	if _, ok := (JWKS{Keys: []JWK{enc}}).KeyFunc()("e1"); ok {
		t.Fatal("encryption key offered for signature verification")
	}
}

func TestSignerRequiresKey(t *testing.T) {
	if _, err := (Signer{}).Sign(valid()); err == nil {
		t.Fatal("signed without a key")
	}
}

// FuzzVerify feeds arbitrary strings to the parser: it must never panic and
// never accept anything other than the one genuine token.
func FuzzVerify(f *testing.F) {
	good := sign(f, valid())
	f.Add(good)
	f.Add("a.b.c")
	f.Add("..")
	f.Add(strings.Replace(good, ".", "..", 1))
	f.Add(forge(map[string]any{"alg": "none"}, valid(), func(string) []byte { return nil }))
	f.Fuzz(func(t *testing.T, token string) {
		c, err := Verify(token, keys, check())
		if err == nil && token != good {
			t.Fatalf("accepted a token that was never issued: %q -> %+v", token, c)
		}
	})
}
