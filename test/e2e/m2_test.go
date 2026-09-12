package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/agent/checkin"
	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/identity"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// fakeCollector returns a fixed document with a fresh collection time.
type fakeCollector struct{ inv protocol.Inventory }

func (f fakeCollector) Collect(context.Context) (protocol.Inventory, error) {
	inv := f.inv
	inv.CollectedAt = time.Now().UTC()
	return inv, nil
}

// fakeRunner echoes the script, or blocks when asked to, so timeouts are
// deterministic without running PowerShell.
type fakeRunner struct{}

func (fakeRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	if script == "sleep" {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	fmt.Fprintf(stdout, "ran: %s", script)
	return 0, nil
}

type fakeRestarter struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (f *fakeRestarter) Restart(d time.Duration, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays = append(f.delays, d)
	return nil
}

func (f *fakeRestarter) calls() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.delays...)
}

func TestInventoryCommandsRenewalUnenroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 2 * time.Minute,
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	defer srv.Close()
	q := a.Store.Q()

	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "m2", CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	idStore := identity.Store{Dir: dir, Keys: identity.PlainKeys{}}
	id, err := enrollment.Enroll(ctx, enrollment.Options{
		ServerURL: srv.URL, Token: token, Pin: pki.Fingerprint(a.CA.Cert().Raw),
		Facts: protocol.DeviceFacts{Hostname: "PC-M2", SMBIOSUUID: "UUID-M2"}, Store: idStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.MustParse(id.DeviceID)

	statePath := filepath.Join(dir, "state.db")
	st, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	inv := protocol.Inventory{
		Hostname: "PC-M2",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Book 9", RAMBytes: 16 << 30},
		Disks:    []protocol.Disk{{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 300 << 30, BitLocker: "on"}},
		Software: []protocol.Software{
			{Name: "7-Zip", Version: "24.08", Scope: "machine"},
			{Name: "Git", Version: "2.51.0", Scope: "machine"},
		},
	}
	restarter := &fakeRestarter{}
	newSession := func(ident *identity.Identity, renewBefore time.Duration) *session.Session {
		t.Helper()
		s, err := session.New(session.Config{
			Identity: ident, IDStore: idStore, State: st, Collector: fakeCollector{inv},
			Executor:    &executor.Executor{Runner: fakeRunner{}, Restarter: restarter, Now: time.Now},
			Log:         slog.New(slog.DiscardHandler),
			RenewBefore: renewBefore,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.Start(ctx)
		return s
	}
	sess := newSession(id, 0)

	// 1. The first check-in uploads inventory.
	resp, err := sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || !resp.InventoryDue {
		t.Fatalf("first check-in = %+v, err = %v", resp, err)
	}
	dev, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Manufacturer != "Contoso" || dev.Model != "Book 9" || dev.OSBuild != "26200" {
		t.Fatalf("device after inventory = %+v", dev)
	}
	sw, err := q.ListSoftware(ctx, deviceID)
	if err != nil || len(sw) != 2 {
		t.Fatalf("software rows = %d, err = %v", len(sw), err)
	}
	stored, err := q.GetInventory(ctx, deviceID)
	if err != nil || stored.RAMGB != 16 || stored.DiskFreeGB != 300 {
		t.Fatalf("stored inventory = %+v, err = %v", stored, err)
	}

	// 2. Nothing is due on the next cycle.
	resp, err = sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || resp.InventoryDue || len(resp.Commands) != 0 {
		t.Fatalf("second check-in = %+v, err = %v", resp, err)
	}

	// 3. All four command types run.
	queue := func(typ string, payload any) uuid.UUID {
		t.Helper()
		var raw json.RawMessage
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			raw = b
		}
		c, err := a.Commands.Queue(ctx, commands.QueueOptions{
			DeviceID: deviceID, Type: typ, Payload: raw, CreatedBy: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	hello := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "hello"})
	slow := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "sleep", TimeoutSeconds: 1})
	reboot := queue(protocol.CommandRestart, protocol.RestartPayload{DelaySeconds: 30})
	refresh := queue(protocol.CommandRefreshInventory, nil)

	resp, err = sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || len(resp.Commands) != 4 {
		t.Fatalf("commands delivered = %d, err = %v", len(resp.Commands), err)
	}
	sess.Wait()

	want := map[uuid.UUID]string{
		hello:   store.CommandSucceeded,
		slow:    store.CommandTimedOut,
		reboot:  store.CommandSucceeded,
		refresh: store.CommandSucceeded,
	}
	for id, status := range want {
		c, res, err := a.Commands.Get(ctx, id)
		if err != nil || c.Status != status || res == nil {
			t.Fatalf("command %s = %s (want %s), result = %+v, err = %v", id, c.Status, status, res, err)
		}
	}
	if _, res, _ := a.Commands.Get(ctx, hello); res.Stdout != "ran: hello" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if _, res, _ := a.Commands.Get(ctx, slow); res.ExitCode != -1 {
		t.Fatalf("timed-out command exit code = %d", res.ExitCode)
	}
	if calls := restarter.calls(); len(calls) != 1 || calls[0] != 30*time.Second {
		t.Fatalf("restart calls = %v", calls)
	}
	if resp, err = sess.Checkin(ctx, protocol.CheckinRequest{}); err != nil || len(resp.Commands) != 0 {
		t.Fatalf("finished commands must not be redelivered: %+v, %v", resp, err)
	}

	// 4. A result stored while offline reaches the server at the next check-in.
	offline := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "offline"})
	if _, err := a.Commands.Deliver(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := st.MarkStarted(offline.String(), now); err != nil {
		t.Fatal(err)
	}
	if err := st.QueueResult(state.QueuedResult{CommandID: offline.String(), Result: protocol.CommandResult{
		Status: protocol.ResultSucceeded, Stdout: "from the queue", StartedAt: now, FinishedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCompleted(offline.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	c, res, err := a.Commands.Get(ctx, offline)
	if err != nil || c.Status != store.CommandSucceeded || res == nil || res.Stdout != "from the queue" {
		t.Fatalf("offline command = %+v result = %+v err = %v", c, res, err)
	}
	if pending, _ := st.PendingResults(); len(pending) != 0 {
		t.Fatalf("queue should be empty, has %d", len(pending))
	}

	// 5. The certificate renews, and the superseded one stops working.
	before, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	renewing := newSession(id, 365*24*time.Hour)
	if _, err := renewing.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	after, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if after.CertSerial == before.CertSerial {
		t.Fatal("the certificate serial must change on renewal")
	}
	if after.PrevCertSerial != "" {
		t.Fatalf("using the new certificate must clear the old serial: %q", after.PrevCertSerial)
	}
	reloaded, err := idStore.Load()
	if err != nil || reloaded.CertPEM == id.CertPEM {
		t.Fatalf("the renewed identity must be on disk: %v", err)
	}
	var httpErr *client.HTTPError
	if _, err := sess.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &httpErr) || httpErr.Status != 401 {
		t.Fatalf("a session holding the old certificate must be rejected: %v", err)
	}

	// 6. Unenrolling wipes the local identity and state.
	fresh := newSession(reloaded, 0)
	if _, err := fresh.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Devices.Unenroll(ctx, deviceID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Checkin(ctx, protocol.CheckinRequest{}); !errors.Is(err, checkin.ErrUnenrolled) {
		t.Fatalf("check-in after unenroll = %v", err)
	}
	if _, err := idStore.Load(); !errors.Is(err, identity.ErrNotEnrolled) {
		t.Fatalf("identity must be gone: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file must be gone: %v", err)
	}
}
