package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func certPEM(t *testing.T, cn string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

func TestCertificateValidation(t *testing.T) {
	good, key := certPEM(t, "Contoso Root")
	other, _ := certPEM(t, "Fabrikam Root")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	withKey := good + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	if err := (Setting{Kind: KindCertificate, Store: "root", CertificatePEM: good}).Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	bad := map[string]Setting{
		"no store":         {Kind: KindCertificate, CertificatePEM: good},
		"personal store":   {Kind: KindCertificate, Store: "my", CertificatePEM: good},
		"a private key":    {Kind: KindCertificate, Store: "root", CertificatePEM: withKey},
		"two certificates": {Kind: KindCertificate, Store: "root", CertificatePEM: good + other},
		"not PEM":          {Kind: KindCertificate, Store: "root", CertificatePEM: "hello"},
		"empty":            {Kind: KindCertificate, Store: "root"},
		"a CSR":            {Kind: KindCertificate, Store: "root", CertificatePEM: "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"},
		"garbage DER":      {Kind: KindCertificate, Store: "root", CertificatePEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		"too big":          {Kind: KindCertificate, Store: "root", CertificatePEM: strings.Repeat("x", MaxCertificatePEMBytes+1)},
	}
	for name, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrBadSetting) {
			t.Errorf("%s: err = %v, want ErrBadSetting", name, err)
		}
	}
	if err := (Setting{Kind: KindCertificate, Store: "root", CertificatePEM: withKey}).Validate(); !strings.Contains(err.Error(), "private key") {
		t.Errorf("a private key should be named: %v", err)
	}
}

func TestCertificateIdentity(t *testing.T) {
	a, _ := certPEM(t, "A")
	b, _ := certPEM(t, "B")
	root := Setting{Kind: KindCertificate, Store: "root", CertificatePEM: a}
	// The same certificate, however it is wrapped, is the same setting.
	rewrapped := Setting{Kind: KindCertificate, Store: "root", CertificatePEM: "\r\n" + strings.ReplaceAll(a, "\n", "\r\n")}
	if root.Identity() != rewrapped.Identity() {
		t.Fatalf("%s != %s", root.Identity(), rewrapped.Identity())
	}
	if !strings.HasPrefix(root.Identity(), "certificate:root:") || len(root.Identity()) != len("certificate:root:")+40 {
		t.Fatalf("identity = %s", root.Identity())
	}
	if root.Identity() == (Setting{Kind: KindCertificate, Store: "root", CertificatePEM: b}).Identity() {
		t.Fatal("different certificates share an identity")
	}
	if root.Identity() == (Setting{Kind: KindCertificate, Store: "ca", CertificatePEM: a}).Identity() {
		t.Fatal("different stores share an identity")
	}
}
