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

func TestCommandQueriesAreScopedByTenant(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := newDevice(t, q, "PC-SCOPED-CMD")
	c := store.Command{
		ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, Type: "run_powershell",
		Payload: []byte(`{}`), Status: store.CommandQueued, CreatedBy: "test",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := q.CreateCommand(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertCommandResult(ctx, store.CommandResult{
		CommandID: c.ID, ExitCode: 0, Stdout: "ok", StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetCommand(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the command: %v", err)
	}
	if _, err := q.GetCommandResult(ctx, other, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the result: %v", err)
	}
	if _, err := q.GetCommand(ctx, store.DefaultTenantID, c.ID); err != nil {
		t.Errorf("the owning tenant should still see it: %v", err)
	}

	if ok, err := q.MarkCommandRunning(ctx, other, c.ID, d.ID, now); err != nil || ok {
		t.Errorf("another tenant must not be able to start the command: ok=%v err=%v", ok, err)
	}
	if ok, err := q.CompleteCommand(ctx, other, c.ID, d.ID, store.CommandSucceeded, now); err != nil || ok {
		t.Errorf("another tenant must not be able to complete the command: ok=%v err=%v", ok, err)
	}
	if got, err := q.GetCommand(ctx, store.DefaultTenantID, c.ID); err != nil || got.Status != store.CommandQueued {
		t.Errorf("another tenant's update must leave the row unchanged: %+v %v", got, err)
	}
}

func TestCommands(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := newDevice(t, q, "PC-CMD")
	other := newDevice(t, q, "PC-OTHER")

	mk := func(created time.Time, expires time.Time) store.Command {
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, Type: "run_powershell",
			Payload: []byte(`{"script":"Get-Date"}`), Status: store.CommandQueued,
			CreatedBy: "test", CreatedAt: created, ExpiresAt: expires,
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := mk(now, now.Add(time.Hour))
	c2 := mk(now.Add(time.Second), now.Add(time.Hour))
	stale := mk(now.Add(-3*time.Hour), now.Add(-time.Hour))

	n, err := q.ExpireCommands(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("ExpireCommands = %d, %v", n, err)
	}
	if got, _ := q.GetCommand(ctx, store.DefaultTenantID, stale.ID); got.Status != store.CommandExpired || got.CompletedAt == nil {
		t.Fatalf("stale command = %+v", got)
	}

	pending, err := q.PendingCommands(ctx, d.ID)
	if err != nil || len(pending) != 2 || pending[0].ID != c1.ID || pending[1].ID != c2.ID {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if string(pending[0].Payload) == "" {
		t.Fatal("payload must round-trip")
	}

	if err := q.MarkCommandsDelivered(ctx, []uuid.UUID{c1.ID, c2.ID}, now); err != nil {
		t.Fatal(err)
	}
	got, _ := q.GetCommand(ctx, store.DefaultTenantID, c1.ID)
	if got.Status != store.CommandDelivered || got.DeliveredAt == nil {
		t.Fatalf("delivered = %+v", got)
	}

	ok, err := q.MarkCommandRunning(ctx, store.DefaultTenantID, c1.ID, d.ID, now)
	if err != nil || !ok {
		t.Fatalf("MarkCommandRunning = %v, %v", ok, err)
	}
	if ok, _ = q.MarkCommandRunning(ctx, store.DefaultTenantID, c1.ID, d.ID, now); ok {
		t.Fatal("second MarkCommandRunning must report no change")
	}
	if ok, _ = q.MarkCommandRunning(ctx, store.DefaultTenantID, c2.ID, other.ID, now); ok {
		t.Fatal("a command must not be startable by another device")
	}

	ok, err = q.CompleteCommand(ctx, store.DefaultTenantID, c1.ID, d.ID, store.CommandSucceeded, now)
	if err != nil || !ok {
		t.Fatalf("CompleteCommand = %v, %v", ok, err)
	}
	if ok, _ = q.CompleteCommand(ctx, store.DefaultTenantID, c1.ID, d.ID, store.CommandFailed, now); ok {
		t.Fatal("completing twice must report no change")
	}
	if err := q.InsertCommandResult(ctx, store.CommandResult{
		CommandID: c1.ID, ExitCode: 0, Stdout: "hi", StdoutTruncated: true, StartedAt: now, FinishedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	r, err := q.GetCommandResult(ctx, store.DefaultTenantID, c1.ID)
	if err != nil || r.Stdout != "hi" || !r.StdoutTruncated || !r.FinishedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if _, err := q.GetCommandResult(ctx, store.DefaultTenantID, c2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing result err = %v", err)
	}

	if pending, _ = q.PendingCommands(ctx, d.ID); len(pending) != 1 || pending[0].ID != c2.ID {
		t.Fatalf("pending after completion = %+v", pending)
	}
	list, err := q.ListCommands(ctx, d.ID, 10)
	if err != nil || len(list) != 3 || list[0].ID != c2.ID || list[2].ID != stale.ID {
		t.Fatalf("ListCommands = %+v, err = %v", list, err)
	}
}
