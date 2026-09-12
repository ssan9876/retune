package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreate(context.Background(), FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csrPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCert(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadOrCreatePersists(t *testing.T) {
	ks := FileKeyStore{Dir: t.TempDir()}
	a1, err := LoadOrCreate(context.Background(), ks, now)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := LoadOrCreate(context.Background(), ks, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !a1.Cert().Equal(a2.Cert()) {
		t.Fatal("second LoadOrCreate must load the same CA")
	}
	if !a1.Cert().IsCA {
		t.Fatal("CA cert must have IsCA")
	}
	if !parseCert(t, a1.CertPEM()).Equal(a1.Cert()) {
		t.Fatal("CertPEM must encode Cert")
	}
}

func TestSignClientCSR(t *testing.T) {
	a := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issued, err := a.SignClientCSR(csrPEM(t, key), "dev-1", now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, issued.PEM)
	if cert.Subject.CommonName != "dev-1" || cert.SerialNumber.Text(16) != issued.Serial || !cert.NotAfter.Equal(issued.NotAfter) {
		t.Fatalf("cert CN=%s serial=%s notAfter=%s; issued=%+v", cert.Subject.CommonName, cert.SerialNumber.Text(16), cert.NotAfter, issued)
	}
	if !issued.NotAfter.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Fatalf("NotAfter = %s", issued.NotAfter)
	}
	opts := x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("client cert must verify for ClientAuth: %v", err)
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("client cert must not verify for ServerAuth")
	}
}

func TestSignClientCSRRejects(t *testing.T) {
	a := newCA(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := map[string][]byte{
		"garbage":  []byte("not a csr"),
		"cert pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"rsa key":  csrPEM(t, rsaKey),
		"p384 key": csrPEM(t, p384),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := a.SignClientCSR(in, "dev", now, time.Hour); !errors.Is(err, ErrBadCSR) {
				t.Fatalf("err = %v, want ErrBadCSR", err)
			}
		})
	}
}

func TestIssueServerCert(t *testing.T) {
	a := newCA(t)
	tc, err := a.IssueServerCert([]string{"mdm.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + CA)", len(tc.Certificate))
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"mdm.example.com", "127.0.0.1"} {
		opts := x509.VerifyOptions{DNSName: host, Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err := leaf.Verify(opts); err != nil {
			t.Fatalf("verify for %s: %v", host, err)
		}
	}
}
