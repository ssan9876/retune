package sweeper_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
	"retune/internal/server/sweeper"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// seedExpiredCommand creates a device and a queued command whose TTL has
// already passed, and returns the command ID.
func seedExpiredCommand(t *testing.T, st *store.Store) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	dev := store.Device{
		ID: uuid.New(), Hostname: "sweeper-test", Status: store.DeviceActive,
		CertSerial: "abc", CertExpiresAt: now.Add(24 * time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	cmd := store.Command{
		ID: uuid.New(), DeviceID: dev.ID, Type: "refresh_inventory",
		Payload: []byte(`{}`), Status: store.CommandQueued, CreatedBy: "test",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	if err := st.Q().CreateCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

func TestExpireCommandsJob(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	cmdID := seedExpiredCommand(t, st)

	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now}
	var job sweeper.Job
	for _, j := range sweeper.DefaultJobs(time.Minute) {
		if j.Name == "commands.expire" {
			job = j
		}
	}
	if job.Name == "" {
		t.Fatal("no commands.expire job in DefaultJobs")
	}

	n, ran, err := r.RunOnce(ctx, job)
	if err != nil || !ran {
		t.Fatalf("RunOnce: n=%d ran=%v err=%v", n, ran, err)
	}
	if n < 1 {
		t.Fatalf("expired %d commands, want at least 1", n)
	}

	// The point of the sweeper: this happened with no device check-in.
	got, err := st.Q().GetCommand(ctx, cmdID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.CommandExpired {
		t.Fatalf("status = %q, want %q", got.Status, store.CommandExpired)
	}
}

func TestSessionCleanupJobRuns(t *testing.T) {
	st := storetest.New(t)
	r := &sweeper.Runner{Store: st, Log: discard(), Now: time.Now}
	for _, j := range sweeper.DefaultJobs(time.Minute) {
		if j.Name != "sessions.cleanup" {
			continue
		}
		if _, ran, err := r.RunOnce(context.Background(), j); err != nil || !ran {
			t.Fatalf("sessions.cleanup: ran=%v err=%v", ran, err)
		}
		return
	}
	t.Fatal("no sessions.cleanup job in DefaultJobs")
}

func TestAdvisoryLockSkipsConcurrentRun(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	const lockID = 5274099

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = st.WithAdvisoryLock(ctx, lockID, func(*store.Queries) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	ran, err := st.WithAdvisoryLock(ctx, lockID, func(*store.Queries) error {
		t.Error("the second caller should not have run the job")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("want ran=false while the lock is held")
	}

	close(release)
	<-done

	// Once released, the lock is available again.
	ran, err = st.WithAdvisoryLock(ctx, lockID, func(*store.Queries) error { return nil })
	if err != nil || !ran {
		t.Fatalf("after release: ran=%v err=%v", ran, err)
	}
}
