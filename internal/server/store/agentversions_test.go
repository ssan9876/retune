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

func TestAgentVersionRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: "1.2.3",
		SHA256: "abc123", SizeBytes: 4096, Notes: "first",
		CreatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateAgentVersion(ctx, v); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetAgentVersion(ctx, store.DefaultTenantID, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.2.3" || got.SHA256 != "abc123" || got.SizeBytes != 4096 {
		t.Fatalf("version = %+v", got)
	}

	byVersion, err := q.GetAgentVersionByVersion(ctx, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if byVersion.ID != v.ID {
		t.Errorf("lookup by version found %v, want %v", byVersion.ID, v.ID)
	}

	// The same version twice is a mistake, not a new build. The unique index
	// is the backstop behind any racy pre-check a caller does first, so its
	// violation must come back as the sentinel, not a raw pgx error.
	dup := v
	dup.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateAgentVersion(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("want ErrDuplicate, got %v", err)
	}

	if _, err := q.GetAgentVersion(ctx, store.DefaultTenantID, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing build should be ErrNotFound, got %v", err)
	}

	if err := q.DeleteAgentVersion(ctx, store.DefaultTenantID, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetAgentVersion(ctx, store.DefaultTenantID, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after deletion it should be gone, got %v", err)
	}
}

func TestAgentVersionQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: "9.9.9", SHA256: "x", SizeBytes: 1,
		CreatedAt: time.Now(), CreatedBy: "t",
	}
	if err := q.CreateAgentVersion(ctx, v); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetAgentVersion(ctx, other, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if err := q.DeleteAgentVersion(ctx, other, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetAgentVersion(ctx, store.DefaultTenantID, v.ID); err != nil {
		t.Errorf("another tenant must not delete the row: %v", err)
	}
}

func TestAgentVersionSignatureRoundTrips(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: "1.0.0", SHA256: "ab", SizeBytes: 1,
		CreatedAt: time.Now(), CreatedBy: "t", KeyID: "0123456789abcdef", Signature: "c2ln",
	}
	if err := st.Q().CreateAgentVersion(ctx, v); err != nil {
		t.Fatal(err)
	}
	got, err := st.Q().GetAgentVersion(ctx, store.DefaultTenantID, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != v.KeyID || got.Signature != v.Signature {
		t.Fatalf("got %+v", got)
	}
	rows, _, err := st.Q().ListAgentVersions(ctx, store.Page{})
	if err != nil || len(rows) != 1 || rows[0].Signature != "c2ln" {
		t.Fatalf("list: %v %+v", err, rows)
	}
}
