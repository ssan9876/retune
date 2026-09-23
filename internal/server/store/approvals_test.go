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

func TestApprovalLifecycle(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	newApproval := func(expires time.Time) store.Approval {
		a := store.Approval{
			ID: uuid.Must(uuid.NewV7()), Kind: store.ApprovalCommand, Request: []byte(`{"type":"wipe"}`),
			Summary: "wipe PC-1", RequestedBy: "a@example.com", RequesterID: uuid.New(),
			CreatedAt: now, ExpiresAt: expires,
		}
		if err := q.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	live := newApproval(now.Add(time.Hour))
	stale := newApproval(now.Add(-time.Minute))

	got, err := q.GetApproval(ctx, live.ID)
	if err != nil || got.Status != store.ApprovalPending || got.Summary != "wipe PC-1" || string(got.Request) != `{"type": "wipe"}` {
		t.Fatalf("get = %+v, %v", got, err)
	}

	// Decided once; the second decision loses.
	d, err := q.DecideApproval(ctx, live.ID, store.ApprovalApproved, "b@example.com", "ok", now)
	if err != nil || d.Status != store.ApprovalApproved || d.DecidedBy != "b@example.com" || d.DecidedAt == nil {
		t.Fatalf("decide = %+v, %v", d, err)
	}
	if _, err := q.DecideApproval(ctx, live.ID, store.ApprovalRejected, "c@example.com", "", now); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("second decision: %v", err)
	}
	// An expired one can't be decided, even before ExpireApprovals runs.
	if _, err := q.DecideApproval(ctx, stale.ID, store.ApprovalApproved, "b@example.com", "", now); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("expired decision: %v", err)
	}
	if _, err := q.DecideApproval(ctx, uuid.New(), store.ApprovalApproved, "b@example.com", "", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing decision: %v", err)
	}

	if err := q.SetApprovalResult(ctx, live.ID, store.ApprovalFailed, []byte(`{"error":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if err := q.ExpireApprovals(ctx, now); err != nil {
		t.Fatal(err)
	}
	pending, total, err := q.ListApprovals(ctx, store.ApprovalPending, store.Page{})
	if err != nil || total != 0 || len(pending) != 0 {
		t.Fatalf("pending = %d/%d, %v", len(pending), total, err)
	}
	all, total, err := q.ListApprovals(ctx, "", store.Page{})
	if err != nil || total != 2 {
		t.Fatalf("all = %d, %v", total, err)
	}
	states := map[uuid.UUID]string{}
	for _, a := range all {
		states[a.ID] = a.Status
	}
	if states[live.ID] != store.ApprovalFailed || states[stale.ID] != store.ApprovalExpired {
		t.Fatalf("states = %v", states)
	}
}
