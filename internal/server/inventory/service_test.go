package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/inventory"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func sampleInventory() protocol.Inventory {
	return protocol.Inventory{
		CollectedAt: time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
		Hostname:    "PC-NEW",
		OS:          protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{
			Manufacturer: "Dell Inc.", Model: "Latitude 7440", Serial: "ABC123",
			SMBIOSUUID: "4C4C4544-0044", RAMBytes: 16 << 30,
		},
		Disks: []protocol.Disk{
			{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 200 << 30},
			{Name: "D:", SizeBytes: 100 << 30, FreeBytes: 50 << 30},
		},
		Software: []protocol.Software{
			{Name: "7-Zip", Version: "24.08", Scope: "machine"},
			{Name: "Git", Version: "2.51.0", Scope: "machine"},
		},
	}
}

func TestInventoryService(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := &inventory.Service{Store: st, Now: func() time.Time { return clock }}

	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-OLD", Serial: "KEEP", SMBIOSUUID: "KEEPU",
		Status: store.DeviceActive, CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}

	due, err := svc.Due(ctx, d.ID, "")
	if err != nil || !due {
		t.Fatalf("Due before any upload = %v, %v", due, err)
	}

	inv := sampleInventory()
	hash, err := svc.Ingest(ctx, d.ID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if hash != protocol.InventoryHash(inv) {
		t.Fatalf("hash = %s", hash)
	}

	if due, _ = svc.Due(ctx, d.ID, hash); due {
		t.Fatal("matching hash must not be due")
	}
	if due, _ = svc.Due(ctx, d.ID, "stale-hash"); !due {
		t.Fatal("a different agent hash must be due")
	}
	clock = now.Add(25 * time.Hour)
	if due, _ = svc.Due(ctx, d.ID, hash); !due {
		t.Fatal("inventory older than 24h must be due")
	}
	clock = now

	dev, err := q.GetDevice(ctx, store.DefaultTenantID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "PC-NEW" || dev.Manufacturer != "Dell Inc." || dev.Model != "Latitude 7440" ||
		dev.OSBuild != "26200" || dev.OSVersion != "Microsoft Windows 11 Pro 10.0.26200" ||
		dev.Serial != "ABC123" || dev.SMBIOSUUID != "4C4C4544-0044" {
		t.Fatalf("device after ingest = %+v", dev)
	}

	stored, err := q.GetInventory(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RAMGB != 16 || stored.DiskFreeGB != 250 || !stored.ReceivedAt.Equal(now) ||
		stored.SoftwareHash != protocol.SoftwareHash(inv.Software) {
		t.Fatalf("stored inventory = %+v", stored)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 2 {
		t.Fatalf("software rows = %d", len(sw))
	}

	// A changed package list is written; an unchanged one keeps the rows.
	changed := sampleInventory()
	changed.Software = append(changed.Software, protocol.Software{Name: "Go", Version: "1.27", Scope: "machine"})
	if _, err := svc.Ingest(ctx, d.ID, changed); err != nil {
		t.Fatal(err)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 3 {
		t.Fatalf("software rows after change = %d", len(sw))
	}
	sameSoftware := sampleInventory()
	sameSoftware.Software = changed.Software
	sameSoftware.Disks[0].FreeBytes = 1 << 30
	if _, err := svc.Ingest(ctx, d.ID, sameSoftware); err != nil {
		t.Fatal(err)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 3 {
		t.Fatalf("software rows after unchanged list = %d", len(sw))
	}

	huge := sampleInventory()
	huge.Software = make([]protocol.Software, inventory.MaxSoftwareEntries+1)
	for i := range huge.Software {
		huge.Software[i] = protocol.Software{Name: fmt.Sprintf("app-%d", i), Scope: "machine"}
	}
	if _, err := svc.Ingest(ctx, d.ID, huge); !errors.Is(err, inventory.ErrBadRequest) {
		t.Fatalf("oversized software list err = %v", err)
	}
}
