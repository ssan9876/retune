package release_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"retune/internal/release"
)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestManifestBytesAreFixedForm(t *testing.T) {
	m := release.Manifest{Version: "1.4.0", SHA256: digest("bytes")}
	want := "retune-agent-manifest/v1\nversion=1.4.0\nsha256=" + digest("bytes") + "\n"
	if got := string(m.Bytes()); got != want {
		t.Fatalf("manifest bytes:\n%q\nwant\n%q", got, want)
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	m := release.Manifest{Version: "1.4.0", SHA256: digest("bytes")}
	sig := release.Sign(priv, m)
	if sig.KeyID != priv.Public().ID() || sig.Version != m.Version || sig.SHA256 != m.SHA256 {
		t.Fatalf("signature carries the wrong manifest or key: %+v", sig)
	}
	if err := release.Verify([]release.PublicKey{priv.Public()}, m, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	priv, _ := release.GenerateKey()
	other, _ := release.GenerateKey()
	m := release.Manifest{Version: "1.4.0", SHA256: digest("bytes")}
	sig := release.Sign(priv, m)

	if err := release.Verify(nil, m, sig); !errors.Is(err, release.ErrNoTrustedKeys) {
		t.Errorf("empty trust list: want ErrNoTrustedKeys, got %v", err)
	}
	if err := release.Verify([]release.PublicKey{other.Public()}, m, sig); !errors.Is(err, release.ErrUntrustedKey) {
		t.Errorf("unknown key id: want ErrUntrustedKey, got %v", err)
	}
	tampered := sig
	tampered.Signature = append([]byte(nil), sig.Signature...)
	tampered.Signature[0] ^= 1
	if err := release.Verify([]release.PublicKey{priv.Public()}, m, tampered); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("flipped bit: want ErrBadSignature, got %v", err)
	}
	moved := m
	moved.Version = "1.4.1"
	if err := release.Verify([]release.PublicKey{priv.Public()}, moved, sig); !errors.Is(err, release.ErrManifestMismatch) {
		t.Errorf("different version: want ErrManifestMismatch, got %v", err)
	}
	// A signature for the same version over different bytes is the attack the
	// manifest exists to stop.
	swapped := m
	swapped.SHA256 = digest("other bytes")
	if err := release.Verify([]release.PublicKey{priv.Public()}, swapped, sig); !errors.Is(err, release.ErrManifestMismatch) {
		t.Errorf("different hash: want ErrManifestMismatch, got %v", err)
	}
}

func TestKeyIDIsFirstEightBytesOfSHA256(t *testing.T) {
	priv, _ := release.GenerateKey()
	sum := sha256.Sum256(priv.Public().Raw)
	if got, want := priv.Public().ID(), hex.EncodeToString(sum[:8]); got != want {
		t.Fatalf("key id = %s, want %s", got, want)
	}
	if len(priv.Public().ID()) != 16 {
		t.Fatal("a key id is 16 hex characters")
	}
}

func TestKeysRoundTripThroughEncoding(t *testing.T) {
	priv, _ := release.GenerateKey()
	back, err := release.DecodePrivateKey(priv.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if back.Public().ID() != priv.Public().ID() {
		t.Fatal("a private key re-read from its seed must derive the same public key")
	}
	pub, err := release.DecodePublicKey(priv.Public().Encode())
	if err != nil {
		t.Fatal(err)
	}
	if pub.ID() != priv.Public().ID() {
		t.Fatal("public key encoding round trip changed the key")
	}
	if _, err := release.DecodePublicKey("not base64!"); err == nil {
		t.Error("garbage must not decode as a key")
	}
	if _, err := release.DecodePublicKey("AAAA"); err == nil {
		t.Error("a key of the wrong length must not decode")
	}
}

func TestTrustListParsing(t *testing.T) {
	a, _ := release.GenerateKey()
	b, _ := release.GenerateKey()
	list := " " + a.Public().Encode() + " , " + b.Public().Encode() + ",,"
	keys, err := release.ParseTrustList(list)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].ID() != a.Public().ID() || keys[1].ID() != b.Public().ID() {
		t.Fatalf("parsed %d keys: %+v", len(keys), keys)
	}
	if keys, err := release.ParseTrustList(""); err != nil || len(keys) != 0 {
		t.Errorf("an empty list is empty, not an error: %v %v", keys, err)
	}
	if _, err := release.ParseTrustList(a.Public().Encode() + ",junk"); err == nil {
		t.Error("one bad entry fails the whole list; a half-trusted list is worse than none")
	}
	if got := release.EncodeTrustList(keys); !strings.Contains(got, a.Public().Encode()) || !strings.Contains(got, ",") {
		t.Errorf("encoded list %q", got)
	}
}

func TestSidecarJSON(t *testing.T) {
	priv, _ := release.GenerateKey()
	sig := release.Sign(priv, release.Manifest{Version: "1.4.0", SHA256: digest("bytes")})
	b, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"version":"1.4.0"`, `"sha256":"`, `"key_id":"` + sig.KeyID + `"`, `"signature":"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("sidecar %s lacks %s", b, field)
		}
	}
	back, err := release.DecodeSidecar(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.KeyID != sig.KeyID || string(back.Signature) != string(sig.Signature) {
		t.Fatal("sidecar round trip changed the signature")
	}
	if _, err := release.DecodeSidecar([]byte(`{"version":"1","sha256":"x","key_id":"k","signature":"AAAA"}`)); err == nil {
		t.Error("a signature that is not 64 bytes must be refused at decode time")
	}
	if _, err := release.DecodeSidecar([]byte(`not json`)); err == nil {
		t.Error("garbage must not decode")
	}
}
