package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

var now = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) *enroll.Service {
	t.Helper()
	st := storetest.New(t)
	authority, err := ca.LoadOrCreate(context.Background(), ca.FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	return &enroll.Service{Store: st, CA: authority, Now: func() time.Time { return now }, CertValidity: 90 * 24 * time.Hour}
}

func newCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	q := svc.Store.Q()

	newToken := func(t *testing.T, o enroll.TokenOptions) (string, store.EnrollmentToken) {
		t.Helper()
		o.CreatedBy = "test"
		plain, tok, err := svc.CreateToken(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		return plain, tok
	}

	t.Run("valid token enrolls device", func(t *testing.T) {
		plain, tok := newToken(t, enroll.TokenOptions{Label: "a"})
		facts := protocol.DeviceFacts{Hostname: "PC-1", Serial: "SN-A", SMBIOSUUID: "U-A", OSVersion: "Windows 11"}
		resp, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		d, err := q.GetDevice(ctx, store.DefaultTenantID, uuid.MustParse(resp.DeviceID))
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != store.DeviceActive || d.Hostname != "PC-1" || d.SMBIOSUUID != "U-A" || !d.CertExpiresAt.Equal(now.Add(90*24*time.Hour)) {
			t.Fatalf("device = %+v", d)
		}
		b, _ := pem.Decode([]byte(resp.CertPEM))
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != resp.DeviceID || cert.SerialNumber.Text(16) != d.CertSerial {
			t.Fatalf("cert CN=%s serial=%s, device serial=%s", cert.Subject.CommonName, cert.SerialNumber.Text(16), d.CertSerial)
		}
		opts := x509.VerifyOptions{Roots: svc.CA.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if _, err := cert.Verify(opts); err != nil {
			t.Fatal(err)
		}
		if resp.CAPEM != string(svc.CA.CertPEM()) {
			t.Fatal("response must include CA PEM")
		}
		got, _ := q.GetEnrollmentToken(ctx, store.DefaultTenantID, tok.ID)
		if got.UseCount != 1 {
			t.Fatalf("use count = %d", got.UseCount)
		}
	})

	t.Run("same hardware replaces previous device", func(t *testing.T) {
		plain, _ := newToken(t, enroll.TokenOptions{})
		facts := protocol.DeviceFacts{Hostname: "PC-2", SMBIOSUUID: "U-B"}
		first, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		second, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		old, _ := q.GetDevice(ctx, store.DefaultTenantID, uuid.MustParse(first.DeviceID))
		if old.Status != store.DeviceReplaced || old.ReplacedBy == nil || old.ReplacedBy.String() != second.DeviceID {
			t.Fatalf("old device = %+v", old)
		}
	})

	errCases := []struct {
		name string
		opts enroll.TokenOptions
		prep func(t *testing.T, tok store.EnrollmentToken, plain string)
		want error
	}{
		{name: "revoked token", prep: func(t *testing.T, tok store.EnrollmentToken, _ string) {
			if err := q.RevokeEnrollmentToken(ctx, store.DefaultTenantID, tok.ID, now); err != nil {
				t.Fatal(err)
			}
		}, want: enroll.ErrTokenRevoked},
		{name: "expired token", opts: enroll.TokenOptions{ExpiresAt: ptr(now.Add(-time.Minute))}, want: enroll.ErrTokenExpired},
		{name: "exhausted token", opts: enroll.TokenOptions{MaxUses: ptr(1)}, prep: func(t *testing.T, _ store.EnrollmentToken, plain string) {
			if _, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-3"}}); err != nil {
				t.Fatal(err)
			}
		}, want: enroll.ErrTokenExhausted},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			plain, tok := newToken(t, tc.opts)
			if tc.prep != nil {
				tc.prep(t, tok, plain)
			}
			_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-4"}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("unknown token", func(t *testing.T) {
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: "rt_nope", CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-5"}})
		if !errors.Is(err, enroll.ErrTokenNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bad CSR does not consume token", func(t *testing.T) {
		plain, tok := newToken(t, enroll.TokenOptions{})
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: "garbage", Device: protocol.DeviceFacts{Hostname: "PC-6"}})
		if !errors.Is(err, ca.ErrBadCSR) {
			t.Fatalf("err = %v", err)
		}
		got, _ := q.GetEnrollmentToken(ctx, store.DefaultTenantID, tok.ID)
		if got.UseCount != 0 {
			t.Fatalf("use count = %d, want 0", got.UseCount)
		}
	})

	t.Run("missing hostname", func(t *testing.T) {
		plain, _ := newToken(t, enroll.TokenOptions{})
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t)})
		if !errors.Is(err, enroll.ErrBadRequest) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("create token rejects non-positive max uses", func(t *testing.T) {
		if _, _, err := svc.CreateToken(ctx, enroll.TokenOptions{MaxUses: ptr(0), CreatedBy: "test"}); !errors.Is(err, enroll.ErrBadRequest) {
			t.Fatalf("err = %v", err)
		}
	})

	entries, err := q.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var enrolled int
	for _, e := range entries {
		if e.Action == "device.enrolled" {
			enrolled++
		}
	}
	if enrolled != 4 {
		t.Fatalf("device.enrolled audit entries = %d, want 4", enrolled)
	}
}

func ptr[T any](v T) *T { return &v }
