package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSignJWTVerifiesWithTheJWKS(t *testing.T) {
	c, err := LoadOrCreate(context.Background(), FileKeyStore{Dir: t.TempDir()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, err := c.SignJWT(map[string]any{"sub": "device-1", "compliance": "compliant"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the way a relying party would: from the published key alone.
	keys := c.JWKS()["keys"].([]any)
	jwk := keys[0].(map[string]any)
	dec := func(s any) *big.Int {
		raw, err := base64.RawURLEncoding.DecodeString(s.(string))
		if err != nil || len(raw) != 32 {
			t.Fatalf("coordinate %v: %v", s, err)
		}
		return new(big.Int).SetBytes(raw)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: dec(jwk["x"]), Y: dec(jwk["y"])}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", token)
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]string
	if err := json.Unmarshal(header, &h); err != nil || h["alg"] != "ES256" || h["kid"] != jwk["kid"] || h["kid"] == "" {
		t.Fatalf("header %s, jwk %v", header, jwk)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the signature doesn't verify with the JWKS key")
	}

	var claims map[string]any
	if err := c.VerifyJWT(token, &claims); err != nil || claims["sub"] != "device-1" {
		t.Fatalf("VerifyJWT: %v, %v", claims, err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"device-1","compliance":"compliant","extra":1}`)) + "." + parts[2]
	if err := c.VerifyJWT(tampered, &claims); err == nil {
		t.Fatal("a changed payload must not verify")
	}
	other, _ := LoadOrCreate(context.Background(), FileKeyStore{Dir: t.TempDir()}, time.Now())
	if err := other.VerifyJWT(token, &claims); err == nil || other.KeyID() == c.KeyID() {
		t.Fatal("another CA's key must not verify it")
	}
}
