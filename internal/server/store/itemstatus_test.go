package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestMarkItemSucceededOnceDoesNotOverwriteAnExistingVerdict(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	dev := newDevice(t, st.Q(), "h1")
	item := uuid.Must(uuid.NewV7())
	now := time.Now()

	s := store.ItemStatus{DeviceID: dev.ID, ItemKind: "agent", ItemID: item, Status: store.ItemSucceeded,
		Detail: "running this version", Version: 1, UpdatedAt: now}
	if err := st.Q().MarkItemSucceededOnce(ctx, s); err != nil {
		t.Fatal(err)
	}
	rollup, _ := st.Q().ItemStatusRollup(ctx, "agent", item, store.Unscoped)
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("rollup %v", rollup)
	}
	// A second call is a no-op: the row keeps its first timestamp.
	s.UpdatedAt = now.Add(time.Hour)
	if err := st.Q().MarkItemSucceededOnce(ctx, s); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := st.Q().ListItemStatus(ctx, "agent", item, "", store.Page{}, store.Unscoped)
	if len(rows) != 1 || !rows[0].UpdatedAt.Before(now.Add(time.Minute)) {
		t.Fatalf("rows %+v", rows)
	}
	// A failed verdict is overwritten: the device is demonstrably on the
	// version now, whatever happened before.
	failed := s
	failed.Status = store.ItemFailed
	if err := st.Q().SetItemStatus(ctx, failed); err != nil {
		t.Fatal(err)
	}
	if err := st.Q().MarkItemSucceededOnce(ctx, s); err != nil {
		t.Fatal(err)
	}
	rollup, _ = st.Q().ItemStatusRollup(ctx, "agent", item, store.Unscoped)
	if rollup[store.ItemSucceeded] != 1 || rollup[store.ItemFailed] != 0 {
		t.Fatalf("rollup %v", rollup)
	}
}

func TestListDeviceItemStatus(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	dev := newDevice(t, st.Q(), "h1")
	profileA := uuid.Must(uuid.NewV7())
	profileB := uuid.Must(uuid.NewV7())
	now := time.Now()

	if err := st.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: dev.ID, ItemKind: "profile", ItemID: profileA,
		Status: store.ItemSucceeded, Version: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: dev.ID, ItemKind: "profile", ItemID: profileB,
		Status: store.ItemPending, Version: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// A different kind on the same device must not leak into the result.
	if err := st.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: dev.ID, ItemKind: "agent", ItemID: uuid.Must(uuid.NewV7()),
		Status: store.ItemFailed, Version: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.Q().ListDeviceItemStatus(ctx, dev.ID, "profile")
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]string{profileA: store.ItemSucceeded, profileB: store.ItemPending}
	if len(got) != len(want) || got[profileA] != want[profileA] || got[profileB] != want[profileB] {
		t.Fatalf("got %v, want %v", got, want)
	}

	none, err := st.Q().ListDeviceItemStatus(ctx, dev.ID, "compliance")
	if err != nil || len(none) != 0 {
		t.Fatalf("none: %v %v", err, none)
	}
}
