package attest_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/attest"
	"retune/internal/server/ca"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// TestCompliantRule: compliant is only ever true for an active device that
// is compliant overall. Every other combination - a retired device that was
// compliant, a device nothing has evaluated, one whose state is unknown - is
// not compliant, in both the lookup and the signed statement.
func TestCompliantRule(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	svc := &attest.Service{Store: st, CA: authority, Issuer: "https://mdm.example.com", Now: func() time.Time { return now }}

	policy := store.CompliancePolicy{
		ID: uuid.Must(uuid.NewV7()), Name: "Baseline", Rules: []byte(`[]`),
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
	}
	if err := q.CreateCompliancePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	mk := func(hostname, status, state string) uuid.UUID {
		t.Helper()
		d := store.Device{
			ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: "SN-" + hostname, Status: status,
			CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
		}
		if err := q.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		if state != "" {
			if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
				DeviceID: d.ID, PolicyID: policy.ID, State: state, Failures: []byte(`[]`), EvaluatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return d.ID
	}
	cases := []struct {
		hostname, status, state string
		wantState               string
		want                    bool
	}{
		{"PC-OK", store.DeviceActive, store.ComplianceCompliant, store.ComplianceCompliant, true},
		{"PC-BAD", store.DeviceActive, store.ComplianceNonCompliant, store.ComplianceNonCompliant, false},
		{"PC-UNKNOWN", store.DeviceActive, store.ComplianceUnknown, store.ComplianceUnknown, false},
		{"PC-NEW", store.DeviceActive, "", store.ComplianceNotEvaluated, false},
		{"PC-RETIRED", store.DeviceRetired, store.ComplianceCompliant, store.ComplianceCompliant, false},
		{"PC-GONE", store.DeviceUnenrolled, store.ComplianceCompliant, store.ComplianceCompliant, false},
	}
	for _, c := range cases {
		id := mk(c.hostname, c.status, c.state)

		got, err := svc.Lookup(ctx, store.LookupHostname, c.hostname, store.Unscoped)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].DeviceID != id.String() || got[0].Status != c.status ||
			got[0].Compliance != c.wantState || got[0].Compliant != c.want {
			t.Errorf("lookup %s = %+v, want %s compliant=%v", c.hostname, got, c.wantState, c.want)
		}

		token, _, err := svc.Statement(ctx, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		var claims attest.Claims
		if err := authority.VerifyJWT(token, &claims); err != nil {
			t.Fatal(err)
		}
		if claims.Compliance != c.wantState || claims.Compliant != c.want {
			t.Errorf("statement %s = %+v, want %s compliant=%v", c.hostname, claims, c.wantState, c.want)
		}
	}

	if got, err := svc.Lookup(ctx, store.LookupHostname, "PC-NOBODY", store.Unscoped); err != nil || len(got) != 0 {
		t.Errorf("an unknown hostname: %+v %v", got, err)
	}
	if _, err := svc.Lookup(ctx, "colour", "blue", store.Unscoped); err == nil {
		t.Error("an unknown lookup kind was accepted")
	}
}

// TestStatement covers what a statement says beyond compliance: its
// lifetime (the default and a configured one), who issued it and for whom,
// and the certificate binding, present only when there is a certificate.
func TestStatement(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-ONE", Serial: "SN-1", Status: store.DeviceActive,
		CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	statement := func(ttl time.Duration, cert []byte) (attest.Claims, time.Time) {
		t.Helper()
		svc := &attest.Service{Store: st, CA: authority, Issuer: "https://mdm.example.com", TTL: ttl, Now: func() time.Time { return now }}
		token, exp, err := svc.Statement(ctx, d.ID, cert)
		if err != nil {
			t.Fatal(err)
		}
		var claims attest.Claims
		if err := authority.VerifyJWT(token, &claims); err != nil {
			t.Fatal(err)
		}
		return claims, exp
	}

	claims, exp := statement(0, nil)
	if !exp.Equal(now.Add(attest.DefaultTTL)) || claims.Expires != exp.Unix() ||
		claims.IssuedAt != now.Unix() || claims.NotBefore != now.Unix() {
		t.Errorf("default lifetime: exp %v, claims %+v", exp, claims)
	}
	if claims.Issuer != "https://mdm.example.com" || claims.Subject != d.ID.String() || claims.Audience != attest.Audience ||
		claims.Hostname != "PC-ONE" || claims.Serial != "SN-1" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Confirmation != nil {
		t.Errorf("a statement without a certificate is bound to one: %+v", claims.Confirmation)
	}

	cert := []byte("certificate bytes")
	claims, exp = statement(10*time.Minute, cert)
	if !exp.Equal(now.Add(10*time.Minute)) || claims.Expires != exp.Unix() {
		t.Errorf("configured lifetime: exp %v, claims %+v", exp, claims)
	}
	sum := sha256.Sum256(cert)
	if claims.Confirmation == nil || claims.Confirmation.CertThumbprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("binding = %+v", claims.Confirmation)
	}

	// A negative lifetime is a misconfiguration, not an already-expired
	// statement.
	if _, exp := statement(-time.Minute, nil); !exp.Equal(now.Add(attest.DefaultTTL)) {
		t.Errorf("negative lifetime: exp %v", exp)
	}

	svc := &attest.Service{Store: st, CA: authority}
	if _, _, err := svc.Statement(ctx, uuid.New(), nil); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown device: %v", err)
	}
}
