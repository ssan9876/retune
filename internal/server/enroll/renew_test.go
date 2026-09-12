package enroll_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
)

func TestRenew(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	q := svc.Store.Q()

	plain, _, err := svc.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Enroll(ctx, protocol.EnrollRequest{
		Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-RENEW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(resp.DeviceID)
	before, err := q.GetDevice(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	renewed, err := svc.Renew(ctx, id, before.CertSerial, protocol.RenewRequest{CSRPEM: newCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(renewed.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != resp.DeviceID {
		t.Fatalf("renewed cert CN = %s", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: svc.CA.Pool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("renewed cert must verify: %v", err)
	}

	after, err := q.GetDevice(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.CertSerial == before.CertSerial || after.CertSerial != cert.SerialNumber.Text(16) {
		t.Fatalf("serial = %s (was %s)", after.CertSerial, before.CertSerial)
	}
	if after.PrevCertSerial != before.CertSerial {
		t.Fatalf("prev serial = %s, want %s", after.PrevCertSerial, before.CertSerial)
	}
	if !after.CertExpiresAt.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Fatalf("expiry = %s", after.CertExpiresAt)
	}

	// Renewing again from the superseded certificate keeps it usable.
	if _, err := svc.Renew(ctx, id, after.PrevCertSerial, protocol.RenewRequest{CSRPEM: newCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if again, _ := q.GetDevice(ctx, id); again.PrevCertSerial != before.CertSerial {
		t.Fatalf("prev serial = %s, want the certificate the agent still holds", again.PrevCertSerial)
	}

	if _, err := svc.Renew(ctx, id, after.CertSerial, protocol.RenewRequest{CSRPEM: "garbage"}); !errors.Is(err, ca.ErrBadCSR) {
		t.Fatalf("bad CSR err = %v", err)
	}

	entries, _ := q.ListAudit(ctx, 100)
	var renewals int
	for _, e := range entries {
		if e.Action == "device.cert_renewed" {
			renewals++
		}
	}
	if renewals != 2 {
		t.Fatalf("device.cert_renewed audit entries = %d", renewals)
	}
}
