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

// A finished command older than the cutoff goes, with its result; a newer one
// stays, and so does an old one that has not finished, however old.
func TestDeleteFinishedCommandsBefore(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	d := newDevice(t, q, "RETENTION-CMD")
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(age time.Duration, finish string) uuid.UUID {
		t.Helper()
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, Type: "restart", Payload: []byte(`{}`),
			Status: "queued", CreatedBy: "test", CreatedAt: now.Add(-age), ExpiresAt: now.Add(time.Hour),
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		if finish != "" {
			if _, err := q.CompleteCommand(ctx, store.DefaultTenantID, c.ID, d.ID, finish, now.Add(-age)); err != nil {
				t.Fatal(err)
			}
			if err := q.InsertCommandResult(ctx, store.CommandResult{
				CommandID: c.ID, StartedAt: now.Add(-age), FinishedAt: now.Add(-age),
			}); err != nil {
				t.Fatal(err)
			}
		}
		return c.ID
	}
	old := mk(100*24*time.Hour, "succeeded")
	oldFailed := mk(95*24*time.Hour, "failed")
	recent := mk(time.Hour, "succeeded")
	oldQueued := mk(200*24*time.Hour, "")

	n, err := q.DeleteFinishedCommandsBefore(ctx, now.Add(-90*24*time.Hour), 5000)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v; want 2", n, err)
	}
	for _, id := range []uuid.UUID{old, oldFailed} {
		if _, err := q.GetCommand(ctx, store.DefaultTenantID, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an old finished command should be gone: %v", err)
		}
		if _, err := q.GetCommandResult(ctx, store.DefaultTenantID, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("its result should go with it: %v", err)
		}
	}
	for _, id := range []uuid.UUID{recent, oldQueued} {
		if _, err := q.GetCommand(ctx, store.DefaultTenantID, id); err != nil {
			t.Errorf("a recent or unfinished command must stay: %v", err)
		}
	}
}

// The limit is a batch size: a caller that loops gets everything, a batch at
// a time.
func TestRetentionDeletesHonourTheLimit(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	d := newDevice(t, q, "RETENTION-BATCH")
	old := time.Now().UTC().Add(-200 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		if err := q.InsertScriptRun(ctx, store.ScriptRun{
			ID: uuid.Must(uuid.NewV7()), ScriptID: uuid.Must(uuid.NewV7()), Version: 1, DeviceID: d.ID,
			Status: "succeeded", Phase: "script", StartedAt: old, FinishedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)
	var batches []int64
	for {
		n, err := q.DeleteScriptRunsBefore(ctx, cutoff, 2)
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, n)
		if n < 2 {
			break
		}
	}
	if len(batches) != 3 || batches[0] != 2 || batches[1] != 2 || batches[2] != 1 {
		t.Fatalf("batches = %v, want [2 2 1]", batches)
	}
}

func TestDeleteRunsAndInstallsBefore(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	d := newDevice(t, q, "RETENTION-HISTORY")
	now := time.Now().UTC()
	cutoff := now.Add(-90 * 24 * time.Hour)
	scriptID, appID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, at := range []time.Time{now.Add(-100 * 24 * time.Hour), now} {
		if err := q.InsertScriptRun(ctx, store.ScriptRun{
			ID: uuid.Must(uuid.NewV7()), ScriptID: scriptID, Version: 1, DeviceID: d.ID,
			Status: "succeeded", Phase: "script", StartedAt: at, FinishedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.InsertAppInstall(ctx, store.AppInstall{
			ID: uuid.Must(uuid.NewV7()), AppID: appID, Version: 1, DeviceID: d.ID,
			Intent: "install", Status: "succeeded", StartedAt: at, FinishedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := q.DeleteScriptRunsBefore(ctx, cutoff, 5000); err != nil || n != 1 {
		t.Errorf("script runs deleted %d, %v; want 1", n, err)
	}
	if n, err := q.DeleteAppInstallsBefore(ctx, cutoff, 5000); err != nil || n != 1 {
		t.Errorf("app installs deleted %d, %v; want 1", n, err)
	}
	if runs, total, err := q.ListScriptRuns(ctx, scriptID, nil, store.Page{}, store.Unscoped); err != nil || total != 1 || len(runs) != 1 {
		t.Errorf("the recent run should remain: %d %v", total, err)
	}
	if installs, total, err := q.ListAppInstalls(ctx, appID, nil, store.Page{}, store.Unscoped); err != nil || total != 1 || len(installs) != 1 {
		t.Errorf("the recent install should remain: %d %v", total, err)
	}
}

// Audit rows are stamped by the database, so the cutoff moves instead of the
// rows: one in the past removes nothing, one in the future removes them all.
func TestDeleteAuditBefore(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	for i := 0; i < 3; i++ {
		if err := q.InsertAudit(ctx, store.AuditEntry{Actor: "test", Action: "test.thing"}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := q.DeleteAuditBefore(ctx, time.Now().Add(-time.Hour), 5000); err != nil || n != 0 {
		t.Fatalf("nothing is older than an hour: deleted %d, %v", n, err)
	}
	if n, err := q.DeleteAuditBefore(ctx, time.Now().Add(time.Hour), 5000); err != nil || n != 3 {
		t.Fatalf("deleted %d, %v; want 3", n, err)
	}
}

func TestOutstandingCommandCounts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	d := newDevice(t, q, "RETENTION-COUNTS")
	now := time.Now().UTC()
	for _, finish := range []string{"", "", "succeeded"} {
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, Type: "restart", Payload: []byte(`{}`),
			Status: "queued", CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		if finish != "" {
			if _, err := q.CompleteCommand(ctx, store.DefaultTenantID, c.ID, d.ID, finish, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := q.OutstandingCommandCounts(ctx)
	if err != nil || got["queued"] != 2 || len(got) != 1 {
		t.Fatalf("counts = %v, %v; want only queued=2", got, err)
	}
}
