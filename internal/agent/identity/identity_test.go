package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	raw, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(der))) {
		t.Fatal("identity.json must hold the sealed key, not the raw key")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "key.bin")); !os.IsNotExist(err) {
		t.Fatal("the key must live inside identity.json")
	}

	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "d1" || got.ServerURL != "https://mdm" || got.ServerPin != "sha256:ab" ||
		got.CertPEM != "cert" || got.CAPEM != "ca" || !got.Key.Equal(key) {
		t.Fatalf("loaded identity = %+v", got)
	}

	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Load after Delete = %v", err)
	}
	if err := s.Delete(); err != nil {
		t.Fatalf("Delete must be repeatable: %v", err)
	}
}

func TestLoadLegacyKeyFile(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir, Keys: xorKeys{}}
	key, _, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	sealed, _ := xorKeys{}.Protect(der)
	if err := os.WriteFile(filepath.Join(dir, "key.bin"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := `{"device_id":"d1","server_url":"https://mdm","cert_pem":"cert","ca_pem":"ca"}`
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load()
	if err != nil || !got.Key.Equal(key) {
		t.Fatalf("legacy load = %+v, err = %v", got, err)
	}
	if err := s.Save(got); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.bin")); !os.IsNotExist(err) {
		t.Fatal("saving must clean up the legacy key file")
	}
}

func TestCertNotAfter(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	got, err := id.CertNotAfter()
	if err != nil || !got.Equal(notAfter) {
		t.Fatalf("CertNotAfter = %s, err = %v", got, err)
	}
	if _, err := (&Identity{CertPEM: "junk"}).CertNotAfter(); err == nil {
		t.Fatal("a malformed certificate must error")
	}
}
