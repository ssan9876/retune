package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, st *store.Store, hostname, status string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: status,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestQueueValidation(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	svc := &commands.Service{Store: st, Now: time.Now}
	active := newDevice(t, st, "PC-1", store.DeviceActive)
	retired := newDevice(t, st, "PC-2", store.DeviceRetired)

	cases := map[string]struct {
		opts commands.QueueOptions
		want error
	}{
		"unknown type":    {commands.QueueOptions{DeviceID: active.ID, Type: "nope"}, commands.ErrBadRequest},
		"empty script":    {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{"script":"  "}`)}, commands.ErrBadRequest},
		"bad json":        {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{`)}, commands.ErrBadRequest},
		"timeout too big": {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{"script":"x","timeout_seconds":90000}`)}, commands.ErrBadRequest},
		"long message":    {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRestart, Payload: json.RawMessage(`{"message":"` + strings.Repeat("m", 600) + `"}`)}, commands.ErrBadRequest},
		"retired device":  {commands.QueueOptions{DeviceID: retired.ID, Type: protocol.CommandRefreshInventory}, commands.ErrDeviceNotActive},
		"missing device":  {commands.QueueOptions{DeviceID: uuid.Must(uuid.NewV7()), Type: protocol.CommandRefreshInventory}, commands.ErrNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.opts.CreatedBy = "test"
			if _, err := svc.Queue(ctx, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCommandLifecycle(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	clock := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	svc := &commands.Service{Store: st, Now: func() time.Time { return clock }}
	d := newDevice(t, st, "PC-1", store.DeviceActive)
	other := newDevice(t, st, "PC-2", store.DeviceActive)

	script, err := svc.Queue(ctx, commands.QueueOptions{
		DeviceID: d.ID, Type: protocol.CommandRunPowerShell,
		Payload: json.RawMessage(`{"script":"Get-Date"}`), CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sp protocol.RunPowerShellPayload
	if err := json.Unmarshal(script.Payload, &sp); err != nil || sp.TimeoutSeconds != int(commands.DefaultScriptTimeout/time.Second) {
		t.Fatalf("normalized payload = %s, err = %v", script.Payload, err)
	}
	if !script.ExpiresAt.Equal(clock.Add(commands.DefaultTTL)) {
		t.Fatalf("expires = %s", script.ExpiresAt)
	}
	if _, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandRestart, CreatedBy: "test"}); err != nil {
		t.Fatalf("restart with no payload: %v", err)
	}

	delivered, err := svc.Deliver(ctx, d.ID)
	if err != nil || len(delivered) != 2 || delivered[0].ID != script.ID.String() {
		t.Fatalf("Deliver = %+v, err = %v", delivered, err)
	}
	if again, _ := svc.Deliver(ctx, d.ID); len(again) != 2 {
		t.Fatal("undelivered work must be offered again until it completes")
	}
	if empty, err := svc.Deliver(ctx, other.ID); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("Deliver for idle device = %#v, err = %v", empty, err)
	}

	if err := svc.Start(ctx, d.ID, script.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx, d.ID, script.ID); err != nil {
		t.Fatalf("Start must be idempotent: %v", err)
	}
	if err := svc.Start(ctx, other.ID, script.ID); !errors.Is(err, commands.ErrNotFound) {
		t.Fatalf("Start from another device = %v", err)
	}

	res := protocol.CommandResult{
		Status: protocol.ResultSucceeded, ExitCode: 0,
		Stdout: "ok\x00" + strings.Repeat("x", protocol.MaxOutputBytes),
		Stderr: "warn", StartedAt: clock, FinishedAt: clock.Add(time.Second),
	}
	if err := svc.Complete(ctx, d.ID, script.ID, res); err != nil {
		t.Fatal(err)
	}
	if err := svc.Complete(ctx, d.ID, script.ID, res); err != nil {
		t.Fatalf("re-submitting a result must succeed: %v", err)
	}
	got, stored, err := svc.Get(ctx, script.ID)
	if err != nil || got.Status != store.CommandSucceeded || stored == nil {
		t.Fatalf("command = %+v, result = %+v, err = %v", got, stored, err)
	}
	if len(stored.Stdout) > protocol.MaxOutputBytes || !stored.StdoutTruncated || strings.Contains(stored.Stdout, "\x00") {
		t.Fatalf("stdout len = %d truncated = %v", len(stored.Stdout), stored.StdoutTruncated)
	}
	if err := svc.Complete(ctx, d.ID, script.ID, protocol.CommandResult{Status: "weird"}); !errors.Is(err, commands.ErrBadRequest) {
		t.Fatalf("bad status err = %v", err)
	}
	if err := svc.Complete(ctx, d.ID, uuid.Must(uuid.NewV7()), res); !errors.Is(err, commands.ErrNotFound) {
		t.Fatalf("unknown command err = %v", err)
	}

	if pending, _ := svc.Deliver(ctx, d.ID); len(pending) != 1 {
		t.Fatalf("pending after completion = %d", len(pending))
	}
	clock = clock.Add(commands.DefaultTTL + time.Hour)
	if pending, _ := svc.Deliver(ctx, d.ID); len(pending) != 0 {
		t.Fatalf("expired commands must not be delivered: %d", len(pending))
	}

	entries, err := st.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var queued int
	for _, e := range entries {
		if e.Action == "command.queued" {
			queued++
		}
	}
	if queued != 2 {
		t.Fatalf("command.queued audit entries = %d", queued)
	}
}
