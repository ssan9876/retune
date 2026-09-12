package devices_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, st *store.Store, status string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-1", Status: status,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRetireAndUnenroll(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	svc := &devices.Service{Store: st}

	d := newDevice(t, st, store.DeviceActive)
	if err := svc.Retire(ctx, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Q().GetDevice(ctx, d.ID); got.Status != store.DeviceRetired {
		t.Fatalf("status = %s", got.Status)
	}
	if err := svc.Retire(ctx, d.ID, "admin"); !errors.Is(err, devices.ErrInvalidTransition) {
		t.Fatalf("retiring twice = %v", err)
	}
	// A retired device can still be unenrolled so the agent wipes itself.
	if err := svc.Unenroll(ctx, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Q().GetDevice(ctx, d.ID); got.Status != store.DeviceUnenrolled {
		t.Fatalf("status = %s", got.Status)
	}
	if err := svc.Unenroll(ctx, d.ID, "admin"); !errors.Is(err, devices.ErrInvalidTransition) {
		t.Fatalf("unenrolling twice = %v", err)
	}

	fresh := newDevice(t, st, store.DeviceActive)
	if err := svc.Unenroll(ctx, fresh.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Retire(ctx, uuid.Must(uuid.NewV7()), "admin"); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("missing device = %v", err)
	}

	entries, err := st.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	if seen["device.retired"] != 1 || seen["device.unenrolled"] != 2 {
		t.Fatalf("audit actions = %v", seen)
	}
}
