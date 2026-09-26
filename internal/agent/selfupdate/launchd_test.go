package selfupdate_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// fakeLaunchd stands in for launchctl and plutil: one daemon, whose plist
// ProgramArguments and loaded/running state the commands read and change.
type fakeLaunchd struct {
	mu      sync.Mutex
	argv    []string
	loaded  bool
	running bool
	calls   []string
	// failBootstrap makes bootstrap fail the next time, as for a broken plist.
	failBootstrap bool
}

func (f *fakeLaunchd) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "/usr/bin/plutil" && args[0] == "-extract":
		return json.Marshal(f.argv)
	case name == "/usr/bin/plutil" && args[0] == "-replace":
		var argv []string
		if err := json.Unmarshal([]byte(args[3]), &argv); err != nil {
			return []byte("bad json"), err
		}
		f.argv = argv
		return nil, nil
	case name == "/bin/launchctl" && args[0] == "print":
		if !f.loaded {
			return []byte("Could not find service"), errors.New("exit status 113")
		}
		state := "not running"
		if f.running {
			state = "running"
		}
		return []byte("system/com.retune.agent = {\n\tstate = " + state + "\n}"), nil
	case name == "/bin/launchctl" && args[0] == "bootout":
		f.loaded, f.running = false, false
		return nil, nil
	case name == "/bin/launchctl" && args[0] == "bootstrap":
		if f.failBootstrap {
			f.failBootstrap = false
			return []byte("Bootstrap failed: 5: Input/output error"), errors.New("exit status 5")
		}
		if f.loaded {
			return []byte("service already loaded"), errors.New("exit status 37")
		}
		f.loaded, f.running = true, true
		return nil, nil
	case name == "/bin/launchctl" && (args[0] == "enable" || args[0] == "kickstart"):
		if args[0] == "kickstart" {
			f.running = true
		}
		return nil, nil
	}
	return nil, errors.New("unexpected command " + name)
}

func (f *fakeLaunchd) binary() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.argv[0]
}

func newLaunchd(f *fakeLaunchd) *selfupdate.LaunchdController {
	return &selfupdate.LaunchdController{
		Label: "com.retune.agent", Plist: "/Library/LaunchDaemons/com.retune.agent.plist",
		Run: f.run, Poll: time.Millisecond,
	}
}

// The plist carries the data directory as arguments after the binary; a
// repoint must keep them, or the new build looks for its identity elsewhere.
func TestLaunchdConfigRoundTrip(t *testing.T) {
	f := &fakeLaunchd{argv: []string{"/usr/local/bin/retune-agent", "run", "--data-dir", "/Library/Application Support/Retune"}}
	c := newLaunchd(f)

	bin, args, err := c.Config()
	if err != nil {
		t.Fatal(err)
	}
	if bin != "/usr/local/bin/retune-agent" || strings.Join(args, "|") != "run|--data-dir|/Library/Application Support/Retune" {
		t.Fatalf("Config = %q %q", bin, args)
	}
	next := "/Library/Application Support/Retune/bin/2.0.0/retune-agent"
	if err := c.SetBinPath(next, args); err != nil {
		t.Fatal(err)
	}
	bin, args2, _ := c.Config()
	if bin != next || strings.Join(args2, "|") != strings.Join(args, "|") {
		t.Fatalf("after SetBinPath: %q %q", bin, args2)
	}
}

// Stop must unload the daemon, not just kill it: with KeepAlive, launchd
// would start a killed agent straight back up on the old binary.
func TestLaunchdStopUnloadsAndStartLoads(t *testing.T) {
	f := &fakeLaunchd{argv: []string{"/usr/local/bin/retune-agent", "run"}, loaded: true, running: true}
	c := newLaunchd(f)

	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if running, _ := c.Running(); running || f.loaded {
		t.Fatal("the daemon should be unloaded")
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatalf("stopping a stopped daemon is not an error: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if running, _ := c.Running(); !running {
		t.Fatal("the daemon should be running again")
	}
	// Starting one that is already loaded kickstarts it instead of failing.
	if err := c.Start(); err != nil {
		t.Fatalf("starting a loaded daemon: %v", err)
	}
}

// The whole update on a Mac: the supervisor stops the daemon, repoints the
// plist at the staged build, starts it, and keeps it once it checks in.
func TestSuperviseWithLaunchdKeepsABuildThatChecksIn(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLaunchd{argv: []string{"/usr/local/bin/retune-agent", "run", "--data-dir", dir}, loaded: true, running: true}
	next := dir + "/bin/2.0.0/retune-agent"
	rec := selfupdate.Record{
		ItemID: "v2", FromVersion: "1.0.0", FromBinPath: "/usr/local/bin/retune-agent",
		FromArgs: []string{"run", "--data-dir", dir}, ToVersion: "2.0.0", ToBinPath: next,
		StartedAt: time.Now(), Deadline: time.Now().Add(time.Minute), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	// The new build proves itself by marking the record succeeded once it has
	// checked in; here that happens as soon as launchd is running it.
	go func() {
		for {
			if f.binary() == next {
				if running, _ := newLaunchd(f).Running(); running {
					ok := rec
					ok.Status = selfupdate.StatusSucceeded
					_ = selfupdate.WriteRecord(dir, ok)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	s := &selfupdate.Supervisor{Dir: dir, Control: newLaunchd(f), Log: slog.New(slog.DiscardHandler), Poll: time.Millisecond}
	if err := s.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.binary() != next || !f.running {
		t.Fatalf("the daemon should run the new build, runs %q (running=%v)", f.binary(), f.running)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a settled update leaves no record")
	}
}

// A build that never checks in is taken out again: the plist points back at
// the previous binary with its arguments, and the record says rolled_back.
func TestSuperviseWithLaunchdRollsBackABuildThatNeverChecksIn(t *testing.T) {
	dir := t.TempDir()
	args := []string{"run", "--data-dir", dir}
	f := &fakeLaunchd{argv: append([]string{"/usr/local/bin/retune-agent"}, args...), loaded: true, running: true}
	rec := selfupdate.Record{
		ItemID: "v2", FromVersion: "1.0.0", FromBinPath: "/usr/local/bin/retune-agent", FromArgs: args,
		ToVersion: "2.0.0", ToBinPath: dir + "/bin/2.0.0/retune-agent",
		StartedAt: time.Now(), Deadline: time.Now().Add(20 * time.Millisecond), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}

	s := &selfupdate.Supervisor{Dir: dir, Control: newLaunchd(f), Log: slog.New(slog.DiscardHandler), Poll: time.Millisecond}
	if err := s.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.argv, "|") != "/usr/local/bin/retune-agent|"+strings.Join(args, "|") || !f.running {
		t.Fatalf("the previous build should be back, with its arguments: %q (running=%v)", f.argv, f.running)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusRolledBack {
		t.Fatalf("want a rolled_back record, got %+v", got)
	}
}
