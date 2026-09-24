package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// The CA signs short statements about devices - that one is compliant, say -
// as ES256 JWTs. Whoever relies on them already trusts this CA for the
// devices' own certificates, and checks the signature with the key JWKS
// publishes.

var b64 = base64.RawURLEncoding

// KeyID names the CA's signing key: the first 16 bytes of the SHA-256 of
// its public key, so a new CA is a new kid.
func (c *CA) KeyID() string {
	der, err := x509.MarshalPKIXPublicKey(&c.key.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return b64.EncodeToString(sum[:16])
}

// SignJWT signs claims as a compact ES256 JWT.
func (c *CA) SignJWT(claims any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": c.KeyID()})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS wants r and s as fixed 32-byte big-endian values, not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}

// JWKS is the CA's public key as a JSON Web Key Set.
func (c *CA) JWKS() map[string]any {
	pub := c.key.PublicKey
	size := 32
	return map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": c.KeyID(),
		"x": b64.EncodeToString(pad(pub.X, size)), "y": b64.EncodeToString(pad(pub.Y, size)),
	}}}
}

func pad(n *big.Int, size int) []byte {
	out := make([]byte, size)
	n.FillBytes(out)
	return out
}

// VerifyJWT checks a JWT this CA signed and decodes its claims into v. It
// checks the signature only; the caller checks what the claims say.
func (c *CA) VerifyJWT(token string, v any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return fmt.Errorf("the signature is malformed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&c.key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return fmt.Errorf("the signature doesn't match")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}
