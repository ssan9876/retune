package selfupdate_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// fakeSystemd stands in for systemctl. What the unit runs is whatever the
// drop-in says, or the unit's own ExecStart when there is none -- the same
// rule systemd applies once daemon-reload has read the drop-in.
type fakeSystemd struct {
	mu      sync.Mutex
	dropIns string
	base    []string
	active  bool
	running []string // the command line the running unit was started with
	calls   []string
}

func (f *fakeSystemd) effective() []string {
	b, err := os.ReadFile(filepath.Join(f.dropIns, selfupdate.DropInName))
	if err != nil {
		return f.base
	}
	var argv []string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok && v != "" {
			argv = strings.Fields(strings.ReplaceAll(v, `"`, ""))
		}
	}
	return argv
}

func (f *fakeSystemd) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name != "systemctl" {
		return nil, errors.New("unexpected command " + name)
	}
	switch args[0] {
	case "show":
		argv := strings.Join(f.base, " ")
		return []byte("{ path=" + f.base[0] + " ; argv[]=" + argv + " ; ignore_errors=no ; start_time=[n/a] ; pid=0 }\n"), nil
	case "daemon-reload":
		return nil, nil
	case "stop":
		f.active, f.running = false, nil
		return nil, nil
	case "start":
		f.active, f.running = true, f.effective()
		return nil, nil
	case "is-active":
		if f.active {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("exit status 3")
	}
	return nil, errors.New("unexpected systemctl " + args[0])
}

func (f *fakeSystemd) runningBinary() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.running) == 0 {
		return ""
	}
	return f.running[0]
}

func newSystemd(t *testing.T, f *fakeSystemd) *selfupdate.SystemdController {
	f.dropIns = filepath.Join(t.TempDir(), "retune-agent.service.d")
	return &selfupdate.SystemdController{Unit: "retune-agent.service", DropInDir: f.dropIns, Run: f.run}
}

// Before any update the unit's own ExecStart is the configuration; after
// SetBinPath a drop-in overrides it, and the unit file is never touched.
func TestSystemdConfigFromUnitThenDropIn(t *testing.T) {
	f := &fakeSystemd{base: []string{"/usr/local/bin/retune-agent", "run", "--data-dir", "/var/lib/retune"}}
	c := newSystemd(t, f)

	bin, args, err := c.Config()
	if err != nil {
		t.Fatal(err)
	}
	if bin != "/usr/local/bin/retune-agent" || strings.Join(args, " ") != "run --data-dir /var/lib/retune" {
		t.Fatalf("Config from the unit = %q %q", bin, args)
	}
	next := "/var/lib/retune/bin/2.0.0/retune-agent"
	if err := c.SetBinPath(next, args); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(f.dropIns, selfupdate.DropInName))
	if err != nil {
		t.Fatal(err)
	}
	// ExecStart= first: without the reset, systemd would refuse a second
	// ExecStart for a simple service.
	if !strings.Contains(string(b), "ExecStart=\nExecStart="+next+" run --data-dir /var/lib/retune\n") {
		t.Fatalf("drop-in:\n%s", b)
	}
	bin, args2, err := c.Config()
	if err != nil || bin != next || strings.Join(args2, " ") != strings.Join(args, " ") {
		t.Fatalf("Config from the drop-in = %q %q %v", bin, args2, err)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "systemctl daemon-reload") {
		t.Error("systemd must be told to reread the unit")
	}
}

// Arguments with spaces or systemd's special characters survive the round
// trip through the drop-in.
func TestSystemdQuotingRoundTrip(t *testing.T) {
	f := &fakeSystemd{base: []string{"/x"}}
	c := newSystemd(t, f)
	want := []string{"run", "--data-dir", "/srv/my agent/100% $HOME", `quote"d`}
	if err := c.SetBinPath("/opt/retune agent/bin", want); err != nil {
		t.Fatal(err)
	}
	bin, args, err := c.Config()
	if err != nil {
		t.Fatal(err)
	}
	if bin != "/opt/retune agent/bin" || strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("round trip = %q %q", bin, args)
	}
}

// The whole update on Linux, including the rollback: the unit is repointed
// at the new build, which never checks in, and is put back on the old one.
func TestSuperviseWithSystemdRollsBack(t *testing.T) {
	dir := t.TempDir()
	f := &fakeSystemd{base: []string{"/usr/local/bin/retune-agent", "run", "--data-dir", dir}, active: true}
	c := newSystemd(t, f)
	f.running = f.base
	args := []string{"run", "--data-dir", dir}
	rec := selfupdate.Record{
		ItemID: "v2", FromVersion: "1.0.0", FromBinPath: "/usr/local/bin/retune-agent", FromArgs: args,
		ToVersion: "2.0.0", ToBinPath: dir + "/bin/2.0.0/retune-agent",
		StartedAt: time.Now(), Deadline: time.Now().Add(20 * time.Millisecond), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	s := &selfupdate.Supervisor{Dir: dir, Control: c, Log: slog.New(slog.DiscardHandler), Poll: time.Millisecond}
	if err := s.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.calls, "\n")
	if !strings.Contains(calls, "systemctl start") || f.runningBinary() != "/usr/local/bin/retune-agent" {
		t.Fatalf("the old build should be running again, runs %q; calls:\n%s", f.runningBinary(), calls)
	}
	got, _, _ := selfupdate.ReadRecord(dir)
	if got.Status != selfupdate.StatusRolledBack {
		t.Fatalf("want rolled_back, got %+v", got)
	}
}
