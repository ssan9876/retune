package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// xorKeys is a fake KeyProvider that proves Save seals the key.
type xorKeys struct{}

func (xorKeys) Protect(b []byte) ([]byte, error)   { return xor(b), nil }
func (xorKeys) Unprotect(b []byte) ([]byte, error) { return xor(b), nil }
func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

func TestNewKeyAndCSR(t *testing.T) {
	key, csrPEM, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "PC-1" || csr.CheckSignature() != nil || !key.PublicKey.Equal(csr.PublicKey) {
		t.Fatal("CSR does not match key/hostname")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir(), Keys: xorKeys{}}
	if _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Load on empty dir = %v, want ErrNotEnrolled", err)
	}
	key, _, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{DeviceID: "d1", ServerURL: "https://mdm", ServerPin: "sha256:ab", CertPEM: "cert", CAPEM: "ca", Key: key}
	if err := s.Save(id); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	onDisk, err := os.ReadFile(filepath.Join(s.Dir, "key.bin"))
	if err != nil || bytes.Equal(onDisk, der) {
		t.Fatal("key.bin must hold the sealed key, not raw DER")
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "d1" || got.ServerURL != "https://mdm" || got.ServerPin != "sha256:ab" || got.CertPEM != "cert" || got.CAPEM != "ca" || !got.Key.Equal(key) {
		t.Fatalf("loaded identity = %+v", got)
	}
}
