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

func TestGroupQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := store.Group{
		ID: uuid.Must(uuid.NewV7()), Name: "Scoped Group", Kind: store.GroupStatic,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := q.CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	a, err := q.CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: uuid.Must(uuid.NewV7()),
		GroupID: g.ID, Mode: store.ModeInclude, CreatedAt: now, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetGroup(ctx, other, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the group: %v", err)
	}
	if _, err := q.GetAssignment(ctx, other, a); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the assignment: %v", err)
	}
	changed := g
	changed.Name = "Hacked"
	if err := q.UpdateGroup(ctx, other, changed); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteAssignment(ctx, other, a); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteGroup(ctx, other, g.ID); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetGroup(ctx, store.DefaultTenantID, g.ID)
	if err != nil || got.Name != "Scoped Group" {
		t.Errorf("another tenant must not change or delete the group: %+v %v", got, err)
	}
	if _, err := q.GetAssignment(ctx, store.DefaultTenantID, a); err != nil {
		t.Errorf("the owning tenant's assignment must survive: %v", err)
	}
}
