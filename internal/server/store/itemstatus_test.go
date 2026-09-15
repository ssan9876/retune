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
	rollup, _ := st.Q().ItemStatusRollup(ctx, "agent", item)
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("rollup %v", rollup)
	}
	// A second call is a no-op: the row keeps its first timestamp.
	s.UpdatedAt = now.Add(time.Hour)
	if err := st.Q().MarkItemSucceededOnce(ctx, s); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := st.Q().ListItemStatus(ctx, "agent", item, "", store.Page{})
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
	rollup, _ = st.Q().ItemStatusRollup(ctx, "agent", item)
	if rollup[store.ItemSucceeded] != 1 || rollup[store.ItemFailed] != 0 {
		t.Fatalf("rollup %v", rollup)
	}
}
