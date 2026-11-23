package jwt

import (
	"crypto/rsa"
	"errors"
	"math/big"
)

// JWK is an RSA public key in JSON Web Key form (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK encodes an RSA public key as a signing JWK.
func PublicJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA", Use: "sig", Alg: algRS256, Kid: kid,
		N: b64.EncodeToString(pub.N.Bytes()),
		E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// RSAPublicKey decodes the JWK, refusing non-RSA keys and moduli under 2048 bits.
func (k JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, errors.New("jwt: unsupported key type")
	}
	nb, err := b64.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("jwt: invalid modulus")
	}
	eb, err := b64.DecodeString(k.E)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("jwt: invalid exponent")
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < 2048 {
		return nil, errors.New("jwt: RSA key shorter than 2048 bits")
	}
	e := int(new(big.Int).SetBytes(eb).Int64())
	if e < 3 || e%2 == 0 {
		return nil, errors.New("jwt: invalid exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// KeyFunc returns a resolver over the usable signing keys in the set.
func (s JWKS) KeyFunc() KeyFunc {
	keys := make(map[string]*rsa.PublicKey, len(s.Keys))
	for _, k := range s.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub, err := k.RSAPublicKey(); err == nil {
			keys[k.Kid] = pub
		}
	}
	return func(kid string) (*rsa.PublicKey, bool) {
		pub, ok := keys[kid]
		return pub, ok
	}
}
