package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestTokenQueriesAreScopedByTenant(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tok := store.EnrollmentToken{ID: uuid.Must(uuid.NewV7()), TokenHash: []byte("hash-scoped"), Label: "scoped", CreatedBy: "test"}
	if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetEnrollmentToken(ctx, other, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if err := q.IncrementTokenUse(ctx, other, tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := q.RevokeEnrollmentToken(ctx, other, tok.ID, now); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetEnrollmentToken(ctx, store.DefaultTenantID, tok.ID)
	if err != nil || got.UseCount != 0 || got.RevokedAt != nil {
		t.Errorf("another tenant must not change the row: %+v %v", got, err)
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	url := storetest.EmptyDatabaseURL(t)
	if err := store.Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := store.Migrate(url); err != nil {
		t.Fatalf("second migrate should be a no-op: %v", err)
	}
	s, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Enrollment tokens.
	maxUses := 3
	tok := store.EnrollmentToken{ID: uuid.Must(uuid.NewV7()), TokenHash: []byte("hash-1"), Label: "lab", MaxUses: &maxUses, CreatedBy: "test"}
	if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := q.IncrementTokenUse(ctx, store.DefaultTenantID, tok.ID); err != nil {
		t.Fatal(err)
	}
	err = s.InTx(ctx, func(q *store.Queries) error {
		got, err := q.GetEnrollmentTokenByHashForUpdate(ctx, []byte("hash-1"))
		if err != nil {
			return err
		}
		if got.ID != tok.ID || got.UseCount != 1 || got.MaxUses == nil || *got.MaxUses != 3 || got.Label != "lab" {
			t.Errorf("token = %+v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetEnrollmentTokenByHashForUpdate(ctx, []byte("missing")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing token err = %v", err)
	}
	if err := q.RevokeEnrollmentToken(ctx, store.DefaultTenantID, tok.ID, now); err != nil {
		t.Fatal(err)
	}
	got, err := q.GetEnrollmentToken(ctx, store.DefaultTenantID, tok.ID)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Fatalf("revoked token = %+v, err = %v", got, err)
	}

	// Devices.
	d1 := store.Device{ID: uuid.Must(uuid.NewV7()), Hostname: "PC-1", Serial: "SN1", SMBIOSUUID: "U1", Status: store.DeviceActive, CertSerial: "abc", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now}
	if err := q.CreateDevice(ctx, d1); err != nil {
		t.Fatal(err)
	}
	for _, hw := range [][2]string{{"", "U1"}, {"SN1", ""}, {"SN1", "U1"}} {
		found, err := q.FindActiveDeviceByHardware(ctx, store.DefaultTenantID, hw[0], hw[1])
		if err != nil || found.ID != d1.ID {
			t.Fatalf("FindActiveDeviceByHardware(%q,%q) = %v, %v", hw[0], hw[1], found.ID, err)
		}
	}
	for _, hw := range [][2]string{{"", ""}, {"SN-x", "U-x"}} {
		if _, err := q.FindActiveDeviceByHardware(ctx, store.DefaultTenantID, hw[0], hw[1]); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("FindActiveDeviceByHardware(%q,%q) err = %v, want ErrNotFound", hw[0], hw[1], err)
		}
	}

	d2 := d1
	d2.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateDevice(ctx, d2); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkDeviceReplaced(ctx, store.DefaultTenantID, d1.ID, d2.ID); err != nil {
		t.Fatal(err)
	}
	old, err := q.GetDevice(ctx, store.DefaultTenantID, d1.ID)
	if err != nil || old.Status != store.DeviceReplaced || old.ReplacedBy == nil || *old.ReplacedBy != d2.ID {
		t.Fatalf("replaced device = %+v, err = %v", old, err)
	}

	if err := q.RecordCheckin(ctx, store.DefaultTenantID, d2.ID, "1.2.3", now); err != nil {
		t.Fatal(err)
	}
	cur, err := q.GetDevice(ctx, store.DefaultTenantID, d2.ID)
	if err != nil || cur.LastSeenAt == nil || !cur.LastSeenAt.Equal(now) || cur.AgentVersion != "1.2.3" {
		t.Fatalf("after checkin = %+v, err = %v", cur, err)
	}
	if _, err := q.GetDevice(ctx, store.DefaultTenantID, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing device err = %v", err)
	}

	// Transactions roll back on error.
	boom := errors.New("boom")
	err = s.InTx(ctx, func(q *store.Queries) error {
		if err := q.SetDeviceStatus(ctx, store.DefaultTenantID, d2.ID, store.DeviceRetired); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("InTx err = %v", err)
	}
	if cur, _ := q.GetDevice(ctx, store.DefaultTenantID, d2.ID); cur.Status != store.DeviceActive {
		t.Fatalf("status after rollback = %s", cur.Status)
	}

	// Audit log.
	if err := q.InsertAudit(ctx, store.AuditEntry{Actor: "test", Action: "thing.done", TargetKind: "device", TargetID: d2.ID.String(), Details: map[string]any{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := q.ListAudit(ctx, 10)
	if err != nil || len(entries) != 1 || entries[0].Action != "thing.done" || entries[0].Details["k"] != "v" {
		t.Fatalf("audit = %+v, err = %v", entries, err)
	}
}
