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

// fakeControl records what was done to the service, and lets a test decide
// what happens when it is started.
//
// failStopOnCall and failStartOnCall pick which call (1-based; 0 means never)
// to Stop or Start returns stopErr/startErr on: a rollback calls both of
// those methods a second time, so a static "always fails" flag can only ever
// exercise the first call and can never drive a failure inside rollback
// itself.
type fakeControl struct {
	mu                   sync.Mutex
	binPath              string
	args                 []string
	calls                []string
	running              bool
	recovery             bool
	stopCalls            int
	startCalls           int
	setBinPathCalls      int
	failStopOnCall       int
	failStartOnCall      int
	failSetBinPathOnCall int
	stopErr              error
	startErr             error
	setBinPathErr        error
	recoveryErr          error
	configErr            error
	// onStart runs when the service is started, standing in for the new agent
	// coming up and doing something.
	onStart func()
}

func (f *fakeControl) Config() (string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.configErr != nil {
		return "", nil, f.configErr
	}
	return f.binPath, f.args, nil
}

func (f *fakeControl) SetBinPath(p string, args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setBinPathCalls++
	f.calls = append(f.calls, "setbinpath:"+p)
	if f.failSetBinPathOnCall != 0 && f.setBinPathCalls == f.failSetBinPathOnCall {
		return f.setBinPathErr
	}
	f.binPath, f.args = p, args
	return nil
}

func (f *fakeControl) SetRecoveryActions() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "recovery")
	if f.recoveryErr != nil {
		return f.recoveryErr
	}
	f.recovery = true
	return nil
}

func (f *fakeControl) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	f.calls = append(f.calls, "stop")
	if f.failStopOnCall != 0 && f.stopCalls == f.failStopOnCall {
		return f.stopErr
	}
	f.running = false
	return nil
}

func (f *fakeControl) Start() error {
	f.mu.Lock()
	f.startCalls++
	fail := f.failStartOnCall != 0 && f.startCalls == f.failStartOnCall
	start := f.onStart
	f.calls = append(f.calls, "start")
	if fail {
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

	// A frozen clock an hour short of the deadline: the check-in lands a few
	// polls in, and on a loaded machine a real clock could reach the deadline
	// first and roll back an update this test says succeeded.
	s := supervisor(dir, c)
	s.Now = func() time.Time { return rec.Deadline.Add(-time.Hour) }

	if err := s.Supervise(context.Background()); err != nil {
		t.Fatalf("a successful update should not error: %v", err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a settled update should leave no record behind")
	}
}

// Every update stages another copy of the agent under bin/, and nothing else
// ever removes one: without this the data directory grows by a whole binary
// per release, for the life of the device. The build that just won and the
// one it replaced both stay -- the second is what a rollback needs.
func TestSuperviseRemovesBuildsNobodyNeedsAnyMore(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"0.8.0", "0.9.0", rec.FromVersion, rec.ToVersion} {
		if err := os.MkdirAll(filepath.Join(dir, "bin", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}
	c.onStart = func() {
		done := rec
		done.Status = selfupdate.StatusSucceeded
		_ = selfupdate.WriteRecord(dir, done)
	}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	want := map[string]bool{rec.FromVersion: true, rec.ToVersion: true}
	if len(left) != len(want) {
		t.Fatalf("bin/ holds %v, want only the new build and the one it can go back to", left)
	}
	for _, name := range left {
		if !want[name] {
			t.Errorf("bin/%s should have been pruned", name)
		}
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
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs, failStopOnCall: 1, stopErr: errors.New("it will not stop")}

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
	// Nothing was touched, so the old build is still wired in and still
	// running: this attempt is over, and saying so is what lets the agent
	// report it. Left pending, it would wedge the device instead -- Decide
	// answers "already under way" forever with no supervisor left to resolve
	// it.
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusRolledBack {
		t.Fatalf("a service that would not stop must still be recorded, got %+v (found=%v)", got, found)
	}
	if !strings.Contains(got.Detail, "would not stop") {
		t.Errorf("detail should say the service would not stop, got %q", got.Detail)
	}
}

// Every step after the service is stopped leaves the device somewhere it
// cannot stay: stopped, or pointed at a build that has not been proven. Each
// one must put the previous build back and record the attempt, rather than
// returning and abandoning the machine mid-update.
func TestSuperviseRestoresWhenAStepAfterStopFails(t *testing.T) {
	cases := map[string]func(c *fakeControl){
		"repointing at the new build fails": func(c *fakeControl) {
			c.failSetBinPathOnCall, c.setBinPathErr = 1, errors.New("access denied")
		},
		"setting recovery actions fails": func(c *fakeControl) {
			c.recoveryErr = errors.New("access denied")
		},
		"the new build will not start": func(c *fakeControl) {
			c.failStartOnCall, c.startErr = 1, errors.New("it will not come up")
		},
	}

	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			rec := pending(dir, time.Now().Add(time.Minute))
			if err := selfupdate.WriteRecord(dir, rec); err != nil {
				t.Fatal(err)
			}
			c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}
			fail(c)

			// The restore worked, so the outcome is recorded rather than lost:
			// a rollback is an outcome, not an error.
			if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
				t.Fatalf("a completed restore should not error: %v", err)
			}
			if c.binPath != rec.FromBinPath {
				t.Errorf("binPath = %q, want the previous build restored", c.binPath)
			}
			var starts, stops int
			for _, call := range c.did() {
				switch call {
				case "start":
					starts++
				case "stop":
					stops++
				}
			}
			if stops < 2 || starts < 1 {
				t.Errorf("the previous build must be stopped and started again, got %v", c.did())
			}
			got, found, _ := selfupdate.ReadRecord(dir)
			if !found || got.Status != selfupdate.StatusRolledBack {
				t.Fatalf("the failed attempt must be recorded, got %+v (found=%v)", got, found)
			}
			if got.Detail == "" {
				t.Error("the record should say which step failed")
			}
		})
	}
}

// The branch that matters most: if the rollback itself cannot finish -- the
// device gets stopped on the old image but the restore fails partway -- the
// record must still say so, naming which step failed, or Decide is left
// staring at a permanently pending record with nothing to report and nothing
// to retry.
func TestSuperviseRecordsAFailureInsideRollback(t *testing.T) {
	// The deadline is already past, so the very first poll drives Supervise
	// straight into rollback.
	past := time.Now().Add(-time.Minute)

	// The restore never got as far as repointing, so the service is still
	// wired to the new build. Writing rolled_back there would be a lie: if
	// the recovery actions bring the new build up, it would check in and
	// report "rolled back" while running the version it supposedly rolled
	// back from. Pending is the honest word -- CheckedIn settles it if the
	// new build ever reaches the server, and a starting old build expires it.
	t.Run("stop fails during rollback, leaving the new build wired in", func(t *testing.T) {
		dir := t.TempDir()
		rec := pending(dir, past)
		if err := selfupdate.WriteRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		// Call 1 is step 2's Stop, which must succeed so rollback is even
		// reached. Call 2 is the Stop inside rollback's restore.
		c := &fakeControl{
			binPath: rec.FromBinPath, args: rec.FromArgs,
			failStopOnCall: 2, stopErr: errors.New("stuck stopping the new build"),
		}

		err := supervisor(dir, c).Supervise(context.Background())
		if err == nil {
			t.Fatal("a rollback that cannot stop the service should be an error")
		}
		got, found, _ := selfupdate.ReadRecord(dir)
		if !found || got.Status != selfupdate.StatusPending {
			t.Fatalf("a restore that left the new build wired in must not claim a rollback, got %+v (found=%v)", got, found)
		}
		if !strings.Contains(got.Detail, "stop") {
			t.Errorf("detail should name the stop step that failed, got %q", got.Detail)
		}
		if !strings.Contains(got.Detail, "still wired to the new build") {
			t.Errorf("detail should say where the service actually points, got %q", got.Detail)
		}
	})

	// If the service cannot even be asked where it points, there is nothing
	// to weigh against the record, and the rollback verdict stands.
	t.Run("the service cannot be read after a failed restore", func(t *testing.T) {
		dir := t.TempDir()
		rec := pending(dir, past)
		if err := selfupdate.WriteRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		c := &fakeControl{
			binPath: rec.FromBinPath, args: rec.FromArgs,
			failStopOnCall: 2, stopErr: errors.New("stuck stopping the new build"),
		}
		// Step 2 and step 3 both read nothing from Config, so failing it only
		// affects the check inside rollback.
		c.configErr = errors.New("the service control manager will not answer")

		if err := supervisor(dir, c).Supervise(context.Background()); err == nil {
			t.Fatal("a rollback that cannot stop the service should be an error")
		}
		got, found, _ := selfupdate.ReadRecord(dir)
		if !found || got.Status != selfupdate.StatusRolledBack {
			t.Fatalf("with nothing to contradict it, the rollback stands, got %+v (found=%v)", got, found)
		}
	})

	t.Run("start fails during rollback", func(t *testing.T) {
		dir := t.TempDir()
		rec := pending(dir, past)
		if err := selfupdate.WriteRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		// Call 1 is step 5's Start (the new build), which must succeed.
		// Call 2 is the Start inside rollback's restore, which fails.
		c := &fakeControl{
			binPath: rec.FromBinPath, args: rec.FromArgs,
			failStartOnCall: 2, startErr: errors.New("the previous build will not come back up"),
		}

		err := supervisor(dir, c).Supervise(context.Background())
		if err == nil {
			t.Fatal("a rollback that cannot start the previous build should be an error")
		}
		got, found, _ := selfupdate.ReadRecord(dir)
		if !found || got.Status != selfupdate.StatusRolledBack {
			t.Fatalf("a failed rollback must still be recorded, got %+v (found=%v)", got, found)
		}
		if !strings.Contains(got.Detail, "start") {
			t.Errorf("detail should name the start step that failed, got %q", got.Detail)
		}
	})
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
