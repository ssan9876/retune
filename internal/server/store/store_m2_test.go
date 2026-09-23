package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, q *store.Queries, hostname string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: "SN1", SMBIOSUUID: "U1",
		Status: store.DeviceActive, CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDeviceQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	dev := newDevice(t, q, "scoped")
	replacement := newDevice(t, q, "scoped-replacement")
	other := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := q.GetDevice(ctx, other, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if err := q.SetDeviceStatus(ctx, other, dev.ID, "retired"); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkDeviceReplaced(ctx, other, dev.ID, replacement.ID); err != nil {
		t.Fatal(err)
	}
	if err := q.RecordCheckin(ctx, other, dev.ID, "9.9.9", now); err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateDeviceHardware(ctx, other, dev.ID, store.HardwareInfo{Hostname: "hacked"}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateDeviceCert(ctx, other, dev.ID, "c1", "hacked", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.ClearPrevCertSerial(ctx, other, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.FindActiveDeviceByHardware(ctx, other, dev.Serial, dev.SMBIOSUUID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not match the hardware: %v", err)
	}
	if err := q.UpsertInventory(ctx, store.DeviceInventory{
		DeviceID: dev.ID, CollectedAt: now, ReceivedAt: now, Hash: "h", Data: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetInventory(ctx, other, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the inventory: %v", err)
	}

	got, err := q.GetDevice(ctx, store.DefaultTenantID, dev.ID)
	if err != nil || got.Status == "retired" || got.ReplacedBy != nil || got.AgentVersion == "9.9.9" ||
		got.Hostname == "hacked" || got.CertSerial == "hacked" {
		t.Errorf("another tenant must not change the row: %+v %v", got, err)
	}
}

func TestInventoryAndDeviceUpdates(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := newDevice(t, q, "PC-1")

	if _, err := q.GetInventory(ctx, store.DefaultTenantID, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetInventory before upload = %v", err)
	}

	inv := store.DeviceInventory{
		DeviceID: d.ID, CollectedAt: now, ReceivedAt: now, Hash: "h1", SoftwareHash: "s1",
		Data: []byte(`{"hostname":"PC-1"}`), RAMGB: 15.5, DiskFreeGB: 100.25,
	}
	if err := q.UpsertInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	got, err := q.GetInventory(ctx, store.DefaultTenantID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != "h1" || got.SoftwareHash != "s1" || got.RAMGB != 15.5 || got.DiskFreeGB != 100.25 || !got.CollectedAt.Equal(now) {
		t.Fatalf("inventory = %+v", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(got.Data, &doc); err != nil || doc["hostname"] != "PC-1" {
		t.Fatalf("data = %s, err = %v", got.Data, err)
	}

	inv.Hash, inv.SoftwareHash, inv.RAMGB = "h2", "s2", 32
	if err := q.UpsertInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if got, _ = q.GetInventory(ctx, store.DefaultTenantID, d.ID); got.Hash != "h2" || got.RAMGB != 32 {
		t.Fatalf("after upsert = %+v", got)
	}

	sw := []store.Software{
		{Name: "Zed", Version: "1", Scope: "machine"},
		{Name: "alpha", Version: "2", Publisher: "Acme", Scope: "user"},
	}
	if err := q.ReplaceSoftware(ctx, d.ID, sw); err != nil {
		t.Fatal(err)
	}
	list, err := q.ListSoftware(ctx, d.ID)
	if err != nil || len(list) != 2 || list[0].Name != "alpha" || list[0].Publisher != "Acme" || list[1].Name != "Zed" {
		t.Fatalf("software = %+v, err = %v", list, err)
	}
	if err := q.ReplaceSoftware(ctx, d.ID, sw[:1]); err != nil {
		t.Fatal(err)
	}
	if list, _ = q.ListSoftware(ctx, d.ID); len(list) != 1 {
		t.Fatalf("software after replace = %+v", list)
	}
	if err := q.ReplaceSoftware(ctx, d.ID, nil); err != nil {
		t.Fatal(err)
	}
	if list, _ = q.ListSoftware(ctx, d.ID); len(list) != 0 {
		t.Fatalf("software after empty replace = %+v", list)
	}

	if err := q.UpdateDeviceHardware(ctx, store.DefaultTenantID, d.ID, store.HardwareInfo{
		Hostname: "PC-RENAMED", OSVersion: "Windows 11 Pro 10.0.26200", OSBuild: "26200",
		Manufacturer: "Dell Inc.", Model: "Latitude 7440",
	}); err != nil {
		t.Fatal(err)
	}
	cur, err := q.GetDevice(ctx, store.DefaultTenantID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Hostname != "PC-RENAMED" || cur.Manufacturer != "Dell Inc." || cur.Model != "Latitude 7440" || cur.OSBuild != "26200" {
		t.Fatalf("device = %+v", cur)
	}
	if cur.Serial != "SN1" || cur.SMBIOSUUID != "U1" {
		t.Fatal("empty inventory values must not blank existing identity fields")
	}

	expires := now.Add(90 * 24 * time.Hour)
	if err := q.UpdateDeviceCert(ctx, store.DefaultTenantID, d.ID, "c1", "c2", expires); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetDevice(ctx, store.DefaultTenantID, d.ID); cur.CertSerial != "c2" || cur.PrevCertSerial != "c1" || !cur.CertExpiresAt.Equal(expires) {
		t.Fatalf("after renew = %+v", cur)
	}
	if err := q.ClearPrevCertSerial(ctx, store.DefaultTenantID, d.ID); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetDevice(ctx, store.DefaultTenantID, d.ID); cur.PrevCertSerial != "" {
		t.Fatalf("prev serial = %q", cur.PrevCertSerial)
	}

	if err := q.SetDeviceStatus(ctx, store.DefaultTenantID, d.ID, store.DeviceUnenrolled); err != nil {
		t.Fatalf("unenrolled must be an allowed status: %v", err)
	}
	newDevice(t, q, "PC-2")
	devices, err := q.ListDevices(ctx)
	if err != nil || len(devices) != 2 {
		t.Fatalf("ListDevices = %d devices, err = %v", len(devices), err)
	}
}
