package policy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeCertStore answers the handler's three scripts from a map of
// "Store\THUMBPRINT" entries.
type fakeCertStore struct {
	certs   map[string]bool
	scripts []string
}

var (
	testPath   = regexp.MustCompile(`^Test-Path -LiteralPath 'Cert:\\LocalMachine\\(\w+)\\([0-9A-F]{40})'$`)
	importCert = regexp.MustCompile(`^Import-Certificate -FilePath '(.+)' -CertStoreLocation 'Cert:\\LocalMachine\\(\w+)' \| Out-Null$`)
	removeCert = regexp.MustCompile(`^Remove-Item -LiteralPath 'Cert:\\LocalMachine\\(\w+)\\([0-9A-F]{40})' -ErrorAction SilentlyContinue$`)
)

func (f *fakeCertStore) run(_ context.Context, script string) (string, error) {
	f.scripts = append(f.scripts, script)
	if m := testPath.FindStringSubmatch(script); m != nil {
		if f.certs[m[1]+`\`+m[2]] {
			return "True\r\n", nil
		}
		return "False\r\n", nil
	}
	if m := importCert.FindStringSubmatch(script); m != nil {
		der, err := os.ReadFile(m[1])
		if err != nil {
			return "", err
		}
		f.certs[m[2]+`\`+protocol.Thumbprint(der)] = true
		return "", nil
	}
	if m := removeCert.FindStringSubmatch(script); m != nil {
		delete(f.certs, m[1]+`\`+m[2])
		return "", nil
	}
	return "", nil
}

func TestCertificateHandler(t *testing.T) {
	ctx := context.Background()
	store := &fakeCertStore{certs: map[string]bool{}}
	h := policy.CertificateHandler{Run: store.run, TempDir: t.TempDir()}
	s := protocol.Setting{Kind: protocol.KindCertificate, Store: "root", CertificatePEM: testCertPEM(t, "Contoso Root")}
	key := `Root\` + s.CertificateThumbprint()

	prior, err := h.Get(ctx, s)
	if err != nil || prior.Exists {
		t.Fatalf("Get before = %+v, %v", prior, err)
	}
	if ok, _ := h.Test(ctx, s); ok {
		t.Fatal("Test before = true")
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if !store.certs[key] {
		t.Fatalf("not imported: %v", store.certs)
	}
	if ok, _ := h.Test(ctx, s); !ok {
		t.Fatal("Test after = false")
	}
	// The temp file is gone.
	if entries, _ := os.ReadDir(h.TempDir); len(entries) != 0 {
		t.Fatalf("left %d files", len(entries))
	}
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if store.certs[key] {
		t.Fatal("revert didn't remove what the setting added")
	}

	// A certificate that was there first stays on revert.
	store.certs[key] = true
	prior, _ = h.Get(ctx, s)
	if err := h.Revert(ctx, s, prior); err != nil || !store.certs[key] {
		t.Fatalf("revert removed a certificate that was already there: %v", err)
	}

	// Nothing but a thumbprint and a fixed store name reaches a script.
	for _, script := range store.scripts {
		if strings.Contains(script, "BEGIN CERTIFICATE") {
			t.Fatalf("the PEM reached a script: %s", script)
		}
	}
}

func TestCertificateHandlerStores(t *testing.T) {
	ctx := context.Background()
	store := &fakeCertStore{certs: map[string]bool{}}
	h := policy.CertificateHandler{Run: store.run, TempDir: t.TempDir()}
	pemText := testCertPEM(t, "Contoso Issuing CA")
	for name, want := range map[string]string{"root": "Root", "ca": "CA", "trusted_publisher": "TrustedPublisher"} {
		s := protocol.Setting{Kind: protocol.KindCertificate, Store: name, CertificatePEM: pemText}
		if err := h.Set(ctx, s); err != nil {
			t.Fatal(err)
		}
		if !store.certs[want+`\`+s.CertificateThumbprint()] {
			t.Errorf("%s: not in %s", name, want)
		}
	}
	if err := h.Set(ctx, protocol.Setting{Kind: protocol.KindCertificate, Store: "My", CertificatePEM: pemText}); err == nil {
		t.Error("a store outside the table must be refused")
	}
}
