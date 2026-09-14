package selfupdate_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// fakeControl records what was done to the service, and lets a test decide
// what happens when it is started.
type fakeControl struct {
	mu       sync.Mutex
	binPath  string
	args     []string
	calls    []string
	running  bool
	recovery bool
	stopErr  error
	startErr error
	// onStart runs when the service is started, standing in for the new agent
	// coming up and doing something.
	onStart func()
}

func (f *fakeControl) Config() (string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.binPath, f.args, nil
}

func (f *fakeControl) SetBinPath(p string, args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "setbinpath:"+p)
	f.binPath, f.args = p, args
	return nil
}

func (f *fakeControl) SetRecoveryActions() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.recovery = append(f.calls, "recovery"), true
	return nil
}

func (f *fakeControl) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.running = false
	return nil
}

func (f *fakeControl) Start() error {
	f.mu.Lock()
	start := f.onStart
	f.calls = append(f.calls, "start")
	if f.startErr != nil {
		f.mu.Unlock()
		return f.startErr
	}
	f.running = true
	f.mu.Unlock()
	if start != nil {
		start()
	}
	return nil
}

func (f *fakeControl) Running() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running, nil
}

func (f *fakeControl) Close() error { return nil }

func (f *fakeControl) did() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func pending(dir string, deadline time.Time) selfupdate.Record {
	return selfupdate.Record{
		FromVersion: "1.0.0", FromBinPath: `C:\Program Files\Retune\retune-agent.exe`,
		FromArgs:  []string{"--data-dir", dir},
		ToVersion: "2.0.0", ToBinPath: dir + `\bin\2.0.0\retune-agent.exe`,
		StartedAt: time.Now(), Deadline: deadline, Status: selfupdate.StatusPending,
	}
}

func supervisor(dir string, c selfupdate.ServiceController) *selfupdate.Supervisor {
	return &selfupdate.Supervisor{
		Dir: dir, Control: c, Log: slog.New(slog.DiscardHandler),
		Poll: time.Millisecond,
	}
}

// The happy path: the new agent checks in, which it proves by marking the
// record succeeded, and the update stands.
func TestSuperviseKeepsAnUpdateThatChecksIn(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}
	// Standing in for the new agent reaching the server.
	c.onStart = func() {
		done := rec
		done.Status = selfupdate.StatusSucceeded
		_ = selfupdate.WriteRecord(dir, done)
	}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatalf("a successful update should not error: %v", err)
	}
	if got := c.binPath; got != rec.ToBinPath {
		t.Errorf("binPath = %q, want the new build", got)
	}
	if len(c.args) != 2 || c.args[0] != "--data-dir" {
		t.Errorf("the service arguments must be preserved, got %+v", c.args)
	}
	if !c.recovery {
		t.Error("recovery actions must be set: a WiX-installed service has none")
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a settled update should leave no record behind")
	}
}

// The happy-path test above would pass even for an implementation that only
// checked the record once, right after Start, since onStart writes success
// synchronously before Start returns. This proves Supervise actually keeps
// re-reading the record on each tick: the check-in lands several polls later,
// on its own goroutine, the way a real agent taking a moment to reach the
// server would.
func TestSuperviseKeepsAnUpdateThatChecksInAfterSeveralPolls(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}
	c.onStart = func() {
		go func() {
			time.Sleep(5 * time.Millisecond)
			done := rec
			done.Status = selfupdate.StatusSucceeded
			_ = selfupdate.WriteRecord(dir, done)
		}()
	}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatalf("a successful update should not error: %v", err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a settled update should leave no record behind")
	}
}

// The failure this milestone exists to prevent: the new build starts but never
// reaches the server. The previous one must come back.
func TestSuperviseRollsBackWhenTheNewAgentNeverChecksIn(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(50*time.Millisecond))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatalf("a rollback is an outcome, not an error: %v", err)
	}
	if c.binPath != rec.FromBinPath {
		t.Errorf("binPath = %q, want the previous build restored", c.binPath)
	}
	if len(c.args) != 2 || c.args[1] != dir {
		t.Errorf("the previous arguments must be restored, got %+v", c.args)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusRolledBack {
		t.Fatalf("the rollback must be recorded for the restored agent to report, got %+v", got)
	}
	if got.Detail == "" {
		t.Error("the record should say why it was rolled back")
	}
	// It must actually have been restarted, not merely repointed.
	var starts int
	for _, c := range c.did() {
		if c == "start" {
			starts++
		}
	}
	if starts < 2 {
		t.Errorf("the service should be started twice -- new, then restored -- got %d", starts)
	}
}

// If the service will not stop, nothing is repointed. A half-applied update is
// worse than none.
func TestSuperviseDoesNotRepointIfTheServiceWillNotStop(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs, stopErr: errors.New("it will not stop")}

	if err := supervisor(dir, c).Supervise(context.Background()); err == nil {
		t.Fatal("a service that will not stop should be an error")
	}
	if c.binPath != rec.FromBinPath {
		t.Errorf("nothing should have been repointed, got %q", c.binPath)
	}
	for _, call := range c.did() {
		if len(call) > 11 && call[:11] == "setbinpath:" {
			t.Fatalf("the image path must not be touched, got %v", c.did())
		}
	}
}

// With no record there is nothing to do, and that is not an error: the
// supervisor may be run after an update has already settled.
func TestSuperviseWithNoRecord(t *testing.T) {
	c := &fakeControl{}
	if err := supervisor(t.TempDir(), c).Supervise(context.Background()); err != nil {
		t.Errorf("no record should be a no-op, got %v", err)
	}
	if len(c.did()) != 0 {
		t.Errorf("nothing should have happened, got %v", c.did())
	}
}
