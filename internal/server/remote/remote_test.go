package remote_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/remote"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// Sessions end themselves: one no device joined, one nobody typed into, and
// one that reached its limit.
func TestSessionLimits(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	svc := &remote.Service{Store: st, Now: func() time.Time { return now }}
	d := store.Device{ID: uuid.Must(uuid.NewV7()), Hostname: "PC-1", Serial: "S", SMBIOSUUID: "U",
		Status: store.DeviceActive, CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now}
	if err := st.Q().CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, d.ID, "ops", "  "); !errors.Is(err, remote.ErrBadRequest) {
		t.Fatalf("no reason: %v", err)
	}

	// Never joined.
	s, err := svc.Start(ctx, d.ID, "ops", "ticket 1")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(remote.JoinTimeout + time.Minute)
	if got, _ := svc.Get(ctx, s.ID); got.Status != store.RemoteEnded || got.EndReason == "" {
		t.Fatalf("unjoined = %+v", got)
	}

	// Joined, then left idle.
	s, _ = svc.Start(ctx, d.ID, "ops", "ticket 2")
	if err := svc.Join(ctx, d.ID, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Input(ctx, s.ID, "ops", "hostname\n"); err != nil {
		t.Fatal(err)
	}
	// Another admin may watch, but not type: what runs is on one name.
	if err := svc.Input(ctx, s.ID, "someone-else", "whoami\n"); !errors.Is(err, remote.ErrNotYours) {
		t.Fatalf("input from another admin: %v", err)
	}
	entries, err := st.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, e := range entries {
		if e.Action == "remote_session.input_refused" && e.Actor == "someone-else" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("refused input audited %d times, want 1", refused)
	}
	now = now.Add(protocol.RemoteIdleTimeout - time.Minute)
	if got, _ := svc.Get(ctx, s.ID); got.Status != store.RemoteActive {
		t.Fatalf("still within the idle limit = %+v", got)
	}
	now = now.Add(2 * time.Minute)
	if got, _ := svc.Get(ctx, s.ID); got.Status != store.RemoteEnded {
		t.Fatalf("idle = %+v", got)
	}
	if err := svc.Input(ctx, s.ID, "ops", "more\n"); !errors.Is(err, remote.ErrEnded) {
		t.Fatalf("input after the end: %v", err)
	}

	// Busy, but past the hour.
	s, _ = svc.Start(ctx, d.ID, "ops", "ticket 3")
	_ = svc.Join(ctx, d.ID, s.ID)
	for range 7 {
		now = now.Add(10 * time.Minute)
		_ = svc.Input(ctx, s.ID, "ops", "Get-Date\n")
	}
	if got, _ := svc.Get(ctx, s.ID); got.Status != store.RemoteEnded {
		t.Fatalf("past an hour = %+v", got)
	}

	// Output from the wrong device, or of the wrong kind, is refused.
	s, _ = svc.Start(ctx, d.ID, "ops", "ticket 4")
	if err := svc.Output(ctx, uuid.New(), s.ID, "out", "x"); !errors.Is(err, remote.ErrNotFound) {
		t.Fatalf("another device: %v", err)
	}
	if err := svc.Output(ctx, d.ID, s.ID, "in", "x"); !errors.Is(err, remote.ErrBadRequest) {
		t.Fatalf("output as input: %v", err)
	}
	if err := svc.Input(ctx, s.ID, "ops", string([]byte{0xff, 0xfe})); !errors.Is(err, remote.ErrBadRequest) {
		t.Fatalf("not text: %v", err)
	}
	retired := d
	if err := st.Q().SetDeviceStatus(ctx, store.DefaultTenantID, retired.ID, store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, d.ID, "ops", "ticket 5"); !errors.Is(err, remote.ErrDeviceNotActive) {
		t.Fatalf("a retired device: %v", err)
	}
}
