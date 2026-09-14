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

	got, err := q.GetAgentVersion(ctx, v.ID)
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

	// The same version twice is a mistake, not a new build.
	dup := v
	dup.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateAgentVersion(ctx, dup); err == nil {
		t.Error("a duplicate version should be refused")
	}

	if _, err := q.GetAgentVersion(ctx, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing build should be ErrNotFound, got %v", err)
	}

	if err := q.DeleteAgentVersion(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetAgentVersion(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after deletion it should be gone, got %v", err)
	}
}
