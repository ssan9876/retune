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

func TestProfileQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)
	p := store.Profile{
		ID: uuid.Must(uuid.NewV7()), Name: "Scoped Profile", CurrentVersion: 1,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetProfile(ctx, other, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	changed := p
	changed.Name = "Hacked"
	if err := q.UpdateProfile(ctx, other, changed); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteProfile(ctx, other, p.ID); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetProfile(ctx, store.DefaultTenantID, p.ID)
	if err != nil || got.Name != "Scoped Profile" {
		t.Errorf("another tenant must not change or delete the row: %+v %v", got, err)
	}
}
