package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestListDevicesPage(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(hostname, serial, status string) store.Device {
		d := store.Device{
			ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: serial, Status: status,
			CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
		}
		if err := q.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	mk("PC-ALPHA", "SN-100", store.DeviceActive)
	mk("PC-BETA", "SN-200", store.DeviceActive)
	mk("PC-GAMMA", "SN-300", store.DeviceRetired)
	if err := q.UpdateDeviceHardware(ctx, store.DefaultTenantID, mk("PC-DELTA", "SN-400", store.DeviceActive).ID,
		store.HardwareInfo{Model: "Latitude 7440"}); err != nil {
		t.Fatal(err)
	}

	all, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{})
	if err != nil || len(all) != 4 || total != 4 {
		t.Fatalf("all = %d rows, total = %d, err = %v", len(all), total, err)
	}

	active, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Status: store.DeviceActive})
	if err != nil || len(active) != 3 || total != 3 {
		t.Fatalf("active = %d rows, total = %d, err = %v", len(active), total, err)
	}

	byHost, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "beta"})
	if err != nil || len(byHost) != 1 || byHost[0].Hostname != "PC-BETA" {
		t.Fatalf("hostname search = %+v, err = %v", byHost, err)
	}
	bySerial, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "SN-300"})
	if err != nil || len(bySerial) != 1 || bySerial[0].Hostname != "PC-GAMMA" {
		t.Fatalf("serial search = %+v, err = %v", bySerial, err)
	}
	byModel, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "latitude"})
	if err != nil || len(byModel) != 1 || byModel[0].Hostname != "PC-DELTA" {
		t.Fatalf("model search = %+v, err = %v", byModel, err)
	}
	if none, total, _ := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "nothing"}); len(none) != 0 || total != 0 {
		t.Fatalf("no matches = %d rows, total %d", len(none), total)
	}

	// Paging reports the unpaged total.
	page1, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Page: store.Page{Limit: 2}})
	if err != nil || len(page1) != 2 || total != 4 {
		t.Fatalf("page 1 = %d rows, total = %d, err = %v", len(page1), total, err)
	}
	page2, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Page: store.Page{Limit: 2, Offset: 2}})
	if err != nil || len(page2) != 2 || page2[0].ID == page1[0].ID {
		t.Fatalf("page 2 = %+v, err = %v", page2, err)
	}
}

func TestListCommandsAndTokensAndAudit(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d1 := newDevice(t, q, "PC-1")
	d2 := newDevice(t, q, "PC-2")

	mkCmd := func(device uuid.UUID, status string) store.Command {
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: device, Type: "refresh_inventory",
			Payload: []byte(`{}`), Status: status, CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mkCmd(d1.ID, store.CommandQueued)
	mkCmd(d1.ID, store.CommandSucceeded)
	mkCmd(d2.ID, store.CommandQueued)

	all, total, err := q.ListCommandsPage(ctx, store.CommandFilter{})
	if err != nil || len(all) != 3 || total != 3 {
		t.Fatalf("all commands = %d, total = %d, err = %v", len(all), total, err)
	}
	forDevice, total, err := q.ListCommandsPage(ctx, store.CommandFilter{DeviceID: &d1.ID})
	if err != nil || len(forDevice) != 2 || total != 2 {
		t.Fatalf("device commands = %d, total = %d, err = %v", len(forDevice), total, err)
	}
	queued, _, err := q.ListCommandsPage(ctx, store.CommandFilter{Status: store.CommandQueued})
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued commands = %d, err = %v", len(queued), err)
	}

	for _, label := range []string{"t1", "t2"} {
		if err := q.CreateEnrollmentToken(ctx, store.EnrollmentToken{
			ID: uuid.Must(uuid.NewV7()), TokenHash: []byte("hash-" + label), Label: label, CreatedBy: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := q.ListEnrollmentTokens(ctx)
	if err != nil || len(tokens) != 2 {
		t.Fatalf("tokens = %+v, err = %v", tokens, err)
	}

	for _, action := range []string{"a.one", "a.two", "a.three"} {
		if err := q.InsertAudit(ctx, store.AuditEntry{Actor: "test", Action: action, TargetKind: "device", TargetID: d1.ID.String()}); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := q.ListAuditPage(ctx, store.Page{Limit: 2})
	if err != nil || len(page) != 2 || total != 3 {
		t.Fatalf("audit page = %d rows, total = %d, err = %v", len(page), total, err)
	}
	if page[0].Action != "a.three" {
		t.Fatalf("audit must be newest first, got %s", page[0].Action)
	}
}

func TestPageNormalized(t *testing.T) {
	cases := map[store.Page]store.Page{
		{}:                      {Limit: 50},
		{Limit: 10, Offset: 20}: {Limit: 10, Offset: 20},
		{Limit: 5000}:           {Limit: 200},
		{Limit: -3, Offset: -9}: {Limit: 50},
	}
	for in, want := range cases {
		if got := in.Normalized(); got != want {
			t.Errorf("%+v.Normalized() = %+v, want %+v", in, got, want)
		}
	}
}
