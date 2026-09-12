package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func runOut(t *testing.T, getenv func(string) string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(context.Background(), args, getenv, &out); err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return out.String()
}

func TestDeviceAndCommandCLI(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	e := env(map[string]string{"DATABASE_URL": url})
	if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.Must(uuid.NewV7())
	if err := st.Q().CreateDevice(ctx, store.Device{
		ID: id, Hostname: "PC-CLI", Serial: "SN-CLI", Status: store.DeviceActive,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if out := runOut(t, e, "device", "list"); !strings.Contains(out, "PC-CLI") || !strings.Contains(out, "active") {
		t.Fatalf("device list = %q", out)
	}
	if out := runOut(t, e, "device", "show", id.String()); !strings.Contains(out, "PC-CLI") || !strings.Contains(out, "none yet") {
		t.Fatalf("device show = %q", out)
	}

	out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "run_powershell", "--script", "Get-Date")
	m := regexp.MustCompile(`Command ID: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("command queue = %q", out)
	}
	if out := runOut(t, e, "command", "show", m[1]); !strings.Contains(out, "run_powershell") || !strings.Contains(out, "queued") {
		t.Fatalf("command show = %q", out)
	}
	if out := runOut(t, e, "device", "show", id.String()); !strings.Contains(out, "run_powershell") {
		t.Fatalf("device show must list recent commands: %q", out)
	}

	scriptFile := filepath.Join(t.TempDir(), "task.ps1")
	if err := os.WriteFile(scriptFile, []byte("Write-Output hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "run_powershell", "--script-file", scriptFile); !strings.Contains(out, "Command ID: ") {
		t.Fatalf("queue from file = %q", out)
	}
	if out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "restart", "--delay", "30s", "--message", "patching"); !strings.Contains(out, "Command ID: ") {
		t.Fatalf("queue restart = %q", out)
	}

	if err := run(ctx, []string{"command", "queue", "--device", id.String(), "--type", "bogus"}, e, io.Discard); err == nil {
		t.Fatal("unknown command type must fail")
	}
	if err := run(ctx, []string{"command", "queue", "--device", id.String(), "--type", "run_powershell"}, e, io.Discard); err == nil {
		t.Fatal("run_powershell without a script must fail")
	}
	if err := run(ctx, []string{"device", "show", "not-a-uuid"}, e, io.Discard); err == nil {
		t.Fatal("malformed device ID must fail")
	}

	runOut(t, e, "device", "retire", id.String())
	if d, _ := st.Q().GetDevice(ctx, id); d.Status != store.DeviceRetired {
		t.Fatalf("status after retire = %s", d.Status)
	}
	runOut(t, e, "device", "unenroll", id.String())
	if d, _ := st.Q().GetDevice(ctx, id); d.Status != store.DeviceUnenrolled {
		t.Fatalf("status after unenroll = %s", d.Status)
	}
	if err := run(ctx, []string{"device", "retire", id.String()}, e, io.Discard); err == nil {
		t.Fatal("retiring an unenrolled device must fail")
	}
}
