package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestRemoteActionPayloads(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	svc := &commands.Service{Store: st, Now: time.Now}
	d := newDevice(t, st, "PC-1", store.DeviceActive)

	c, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandLock, CreatedBy: "ops"})
	if err != nil || string(c.Payload) != "{}" {
		t.Fatalf("lock = %s, %v", c.Payload, err)
	}
	c, err = svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandCollectLogs, CreatedBy: "ops"})
	if err != nil || string(c.Payload) != `{"hours":24}` {
		t.Fatalf("collect_logs default = %s, %v", c.Payload, err)
	}
	for _, hours := range []int{-1, 169} {
		raw, _ := json.Marshal(protocol.CollectLogsPayload{Hours: hours})
		if _, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandCollectLogs,
			Payload: raw, CreatedBy: "ops"}); !errors.Is(err, commands.ErrBadRequest) {
			t.Errorf("hours %d = %v", hours, err)
		}
	}
}

func TestWipeGuardrails(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	svc := &commands.Service{Store: st, Now: func() time.Time { return now }}
	d := newDevice(t, st, "LAPTOP-042", store.DeviceActive)
	wipe := func(confirm, reason string, ttl time.Duration) (store.Command, error) {
		return svc.Queue(ctx, commands.QueueOptions{
			DeviceID: d.ID, Type: protocol.CommandWipe, Payload: json.RawMessage(`{"protected":true}`),
			CreatedBy: "ops", ConfirmHostname: confirm, Reason: reason, TTL: ttl,
		})
	}

	if _, err := wipe("LAPTOP-042", "", 0); !errors.Is(err, commands.ErrBadRequest) {
		t.Errorf("no reason = %v", err)
	}
	if _, err := wipe("LAPTOP-043", "stolen", 0); !errors.Is(err, commands.ErrBadRequest) ||
		!strings.Contains(err.Error(), "LAPTOP-042") {
		t.Errorf("wrong hostname = %v", err)
	}
	if _, err := wipe("", "stolen", 0); !errors.Is(err, commands.ErrBadRequest) {
		t.Errorf("no hostname = %v", err)
	}
	if _, err := wipe("laptop-042", strings.Repeat("r", 501), 0); !errors.Is(err, commands.ErrBadRequest) {
		t.Errorf("long reason = %v", err)
	}

	// The hostname matches whatever its case; a week's TTL becomes a day.
	c, err := wipe(" laptop-042 ", "reported stolen, ticket 881", 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(now.Add(commands.WipeTTL)) {
		t.Errorf("expires %v, want %v", c.ExpiresAt, now.Add(commands.WipeTTL))
	}

	entries, err := st.Q().ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "command.wipe_queued" && e.TargetID == c.ID.String() {
			found = true
			if e.Details["reason"] != "reported stolen, ticket 881" || e.Details["hostname"] != "LAPTOP-042" ||
				e.Details["protected"] != true {
				t.Errorf("audit details = %v", e.Details)
			}
		}
	}
	if !found {
		t.Error("no command.wipe_queued audit entry")
	}
}

func TestArtifacts(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	dir := filepath.Join(t.TempDir(), "artifacts")
	now := time.Now()
	svc := &commands.Service{Store: st, Now: func() time.Time { return now }, ArtifactDir: dir}
	d := newDevice(t, st, "PC-1", store.DeviceActive)
	other := newDevice(t, st, "PC-2", store.DeviceActive)

	logs, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandCollectLogs, CreatedBy: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandLock, CreatedBy: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	upload := func(device, command uuid.UUID, body string) error {
		return svc.UploadArtifact(ctx, device, command, strings.NewReader(body))
	}

	// Not running yet.
	if err := upload(d.ID, logs.ID, "zip"); !errors.Is(err, commands.ErrConflict) {
		t.Errorf("before start = %v", err)
	}
	for _, c := range []store.Command{logs, lock} {
		if _, err := svc.Deliver(ctx, d.ID); err != nil {
			t.Fatal(err)
		}
		if err := svc.Start(ctx, d.ID, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := upload(other.ID, logs.ID, "zip"); !errors.Is(err, commands.ErrNotFound) {
		t.Errorf("another device's command = %v", err)
	}
	if err := upload(d.ID, lock.ID, "zip"); !errors.Is(err, commands.ErrConflict) {
		t.Errorf("a lock command = %v", err)
	}
	if err := upload(d.ID, uuid.Must(uuid.NewV7()), "zip"); !errors.Is(err, commands.ErrNotFound) {
		t.Errorf("no such command = %v", err)
	}
	if err := upload(d.ID, logs.ID, "the archive"); err != nil {
		t.Fatal(err)
	}
	if err := upload(d.ID, logs.ID, "a second archive"); !errors.Is(err, commands.ErrConflict) {
		t.Errorf("second upload = %v", err)
	}
	f, a, err := svc.OpenArtifact(ctx, logs.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 64)
	n, _ := f.Read(body)
	f.Close()
	if string(body[:n]) != "the archive" || a.SizeBytes != int64(len("the archive")) || len(a.SHA256) != 64 {
		t.Fatalf("stored %q, %+v", body[:n], a)
	}

	// Too large.
	big, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandCollectLogs, CreatedBy: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	svc.Deliver(ctx, d.ID)
	svc.Start(ctx, d.ID, big.ID)
	if err := svc.UploadArtifact(ctx, d.ID, big.ID, zeros(protocol.MaxLogArchiveBytes+1)); !errors.Is(err, commands.ErrTooLarge) {
		t.Errorf("too large = %v", err)
	}

	// Pruning: an orphan file goes after an hour; the archive after 30 days.
	orphan := filepath.Join(dir, uuid.Must(uuid.NewV7()).String()+".zip")
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * time.Hour)
	os.Chtimes(orphan, old, old)
	if n, err := svc.PruneArtifacts(ctx, now); err != nil || n != 1 {
		t.Fatalf("prune orphans = %d, %v", n, err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Error("the orphan survived")
	}
	if n, err := svc.PruneArtifacts(ctx, now.Add(commands.ArtifactRetention+time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune old = %d, %v", n, err)
	}
	if _, _, err := svc.OpenArtifact(ctx, logs.ID); !errors.Is(err, commands.ErrNotFound) {
		t.Errorf("after pruning = %v", err)
	}
}

type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= int64(len(p))
	return len(p), nil
}

func zeros(n int64) *zeroReader { return &zeroReader{n: n} }
