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

func TestBitLockerQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	d := newDevice(t, q, "BL-SCOPED")
	now := time.Now().UTC().Truncate(time.Microsecond)
	k := store.BitLockerKey{
		ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, VolumeID: "C:", Method: "tpm",
		Ciphertext: []byte("ct"), Nonce: []byte("n"), CreatedAt: now, UpdatedAt: now,
	}
	if err := q.UpsertBitLockerKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetBitLockerKey(ctx, other, k.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if _, err := q.GetBitLockerKey(ctx, store.DefaultTenantID, k.ID); err != nil {
		t.Errorf("the owning tenant should still see the row: %v", err)
	}
}
