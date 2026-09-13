package scripts_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/executor"
	"retune/internal/agent/scripts"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func opts(mutate func(*protocol.DeploymentOptions)) protocol.DeploymentOptions {
	o := protocol.DefaultDeploymentOptions()
	if mutate != nil {
		mutate(&o)
	}
	return o
}

func TestDecide(t *testing.T) {
	cases := map[string]struct {
		version int
		opts    protocol.DeploymentOptions
		state   state.ItemState
		now     time.Time
		wantRun bool
		reason  string // a substring of the reason, when not running
	}{
		"never run before": {
			version: 1, opts: opts(nil), state: state.ItemState{}, now: now, wantRun: true,
		},
		"once, already run": {
			version: 1, opts: opts(nil),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-time.Hour), LastStatus: protocol.ResultSucceeded},
			now:     now,
			wantRun: false, reason: "already run",
		},
		"new version reruns by default": {
			version: 2, opts: opts(nil),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-time.Hour), LastStatus: protocol.ResultSucceeded},
			now:     now,
			wantRun: true,
		},
		"new version held back when rerun is off": {
			version: 2, opts: opts(func(o *protocol.DeploymentOptions) { o.RerunOnNewVersion = false }),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-time.Hour)},
			now:     now,
			wantRun: false, reason: "rerun_on_new_version is off",
		},
		"recurring, not due yet": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) {
				o.Frequency, o.IntervalHours = protocol.FrequencyRecurring, 24
			}),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-2 * time.Hour)},
			now:     now,
			wantRun: false, reason: "not due again yet",
		},
		"recurring, due": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) {
				o.Frequency, o.IntervalHours = protocol.FrequencyRecurring, 24
			}),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-25 * time.Hour)},
			now:     now,
			wantRun: true,
		},
		"recurring, exactly due": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) {
				o.Frequency, o.IntervalHours = protocol.FrequencyRecurring, 24
			}),
			state:   state.ItemState{Version: 1, LastRunAt: now.Add(-24 * time.Hour)},
			now:     now,
			wantRun: true,
		},
		"too many failures on this version": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) {
				o.Frequency, o.IntervalHours, o.MaxRetries = protocol.FrequencyRecurring, 1, 2
			}),
			state: state.ItemState{
				Version: 1, LastRunAt: now.Add(-10 * time.Hour),
				LastStatus: protocol.ResultFailed, Failures: 2,
			},
			now:     now,
			wantRun: false, reason: "failed too many times",
		},
		"a new version clears the failure count": {
			version: 2, opts: opts(func(o *protocol.DeploymentOptions) { o.MaxRetries = 2 }),
			state: state.ItemState{
				Version: 1, LastRunAt: now.Add(-time.Hour),
				LastStatus: protocol.ResultFailed, Failures: 5,
			},
			now:     now,
			wantRun: true,
		},
		"failures below the limit still retry": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) {
				o.Frequency, o.IntervalHours, o.MaxRetries = protocol.FrequencyRecurring, 1, 3
			}),
			state: state.ItemState{
				Version: 1, LastRunAt: now.Add(-2 * time.Hour),
				LastStatus: protocol.ResultFailed, Failures: 1,
			},
			now:     now,
			wantRun: true,
		},
		"running as the signed-in user is not executable yet": {
			version: 1, opts: opts(func(o *protocol.DeploymentOptions) { o.RunAs = protocol.RunAsUser }),
			state:   state.ItemState{},
			now:     now,
			wantRun: false, reason: "not supported yet",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := scripts.Decide(tc.version, tc.opts, tc.state, tc.now)
			if got.Run != tc.wantRun {
				t.Fatalf("Run = %v, want %v (reason %q)", got.Run, tc.wantRun, got.Reason)
			}
			if !tc.wantRun && !strings.Contains(got.Reason, tc.reason) {
				t.Errorf("reason = %q, want it to mention %q", got.Reason, tc.reason)
			}
		})
	}
}

// fakeRunner records what it was asked to run and answers with canned exit
// codes, so detection and remediation can be tested without PowerShell.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	// exits maps a script body to the exit code it should produce.
	exits map[string]int
	// errs maps a body to an error the runner should return.
	errs map[string]error
}

func (f *fakeRunner) RunPowerShell(_ context.Context, script string, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, script)
	if err, ok := f.errs[script]; ok {
		return -1, err
	}
	_, _ = stdout.Write([]byte("ran " + script))
	return f.exits[script], nil
}

func (f *fakeRunner) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeClient serves one script version and captures reported runs.
type fakeClient struct {
	version  protocol.ScriptVersionResponse
	fetches  int
	runs     []protocol.ScriptRun
	fetchErr error
}

func (c *fakeClient) FetchScript(context.Context, string, int) (protocol.ScriptVersionResponse, error) {
	c.fetches++
	if c.fetchErr != nil {
		return protocol.ScriptVersionResponse{}, c.fetchErr
	}
	return c.version, nil
}

func (c *fakeClient) ReportScriptRun(_ context.Context, _ string, run protocol.ScriptRun) error {
	c.runs = append(c.runs, run)
	return nil
}

func newScheduler(t *testing.T, client *fakeClient, runner executor.Runner) (*scripts.Scheduler, *state.Store) {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &scripts.Scheduler{
		State: st, Client: client, Runner: runner, Now: func() time.Time { return now },
	}, st
}

func item(id string, version int, o protocol.DeploymentOptions) protocol.Item {
	raw, err := o.Marshal()
	if err != nil {
		panic(err)
	}
	return protocol.Item{Kind: protocol.ItemKindScript, ID: id, Version: version, Options: raw}
}

func TestSyncRunsAPlainScript(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{Version: 1, Body: "install"}}
	runner := &fakeRunner{exits: map[string]int{"install": 0}}
	s, st := newScheduler(t, client, runner)

	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 1 || got[0] != "install" {
		t.Fatalf("ran %v, want just the body", got)
	}
	if len(client.runs) != 1 {
		t.Fatalf("want one reported run, got %d", len(client.runs))
	}
	run := client.runs[0]
	if run.Status != protocol.ResultSucceeded || run.Phase != protocol.PhaseScript || run.Version != 1 {
		t.Fatalf("run = %+v", run)
	}

	// It does not run again on the next check-in, and the body is not re-fetched.
	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 1 {
		t.Fatalf("a once deployment ran %d times", len(got))
	}
	if client.fetches != 1 {
		t.Errorf("the body should be fetched once per version, got %d fetches", client.fetches)
	}
	if local, _ := st.ItemState("s1"); local.Version != 1 || local.LastStatus != protocol.ResultSucceeded {
		t.Errorf("local state = %+v", local)
	}
}

func TestDetectionPassingSkipsTheBody(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{
		Version: 1, Body: "remediate", DetectionBody: "detect",
	}}
	runner := &fakeRunner{exits: map[string]int{"detect": 0}}
	s, _ := newScheduler(t, client, runner)

	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 1 || got[0] != "detect" {
		t.Fatalf("nothing needed doing, so only detection should run; ran %v", got)
	}
	run := client.runs[0]
	if run.Status != protocol.ResultSucceeded || run.Phase != protocol.PhaseDetection || run.Remediated {
		t.Fatalf("run = %+v", run)
	}
}

func TestDetectionFailingRemediatesThenRechecks(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{
		Version: 1, Body: "remediate", DetectionBody: "detect",
	}}
	// Detection keeps failing, even after remediation runs.
	runner := &fakeRunner{exits: map[string]int{"detect": 1, "remediate": 0}}
	s, _ := newScheduler(t, client, runner)

	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	got := runner.ran()
	if len(got) != 3 || got[0] != "detect" || got[1] != "remediate" || got[2] != "detect" {
		t.Fatalf("want detect, remediate, detect; got %v", got)
	}
	// The second detection still exits 1 here, so the deployment failed.
	run := client.runs[0]
	if run.Status != protocol.ResultFailed || run.Phase != protocol.PhaseDetection {
		t.Fatalf("a machine still failing detection has not been fixed: %+v", run)
	}
	if run.Remediated {
		t.Error("remediated should be false when detection still fails")
	}
}

// healingRunner fails detection until remediation has run, which is what a
// working detect-and-remediate pair looks like.
type healingRunner struct {
	fakeRunner
	fixed bool
}

func (h *healingRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	h.mu.Lock()
	h.calls = append(h.calls, script)
	fixed := h.fixed
	if script == "remediate" {
		h.fixed = true
	}
	h.mu.Unlock()

	_, _ = stdout.Write([]byte("ran " + script))
	if script == "detect" && !fixed {
		return 1, nil
	}
	return 0, nil
}

func TestSuccessfulRemediationIsReported(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{
		Version: 1, Body: "remediate", DetectionBody: "detect",
	}}
	runner := &healingRunner{}
	s, _ := newScheduler(t, client, runner)

	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 3 {
		t.Fatalf("want detect, remediate, detect; got %v", got)
	}
	run := client.runs[0]
	if run.Status != protocol.ResultSucceeded {
		t.Fatalf("the second detection passed, so the run succeeded: %+v", run)
	}
	if !run.Remediated {
		t.Error("remediated should record that work was actually done")
	}
	if !strings.Contains(run.Stdout, "ran remediate") {
		t.Errorf("the remediation output should be kept, got %q", run.Stdout)
	}
}

func TestRunAsUserRunsNothing(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{Version: 1, Body: "install"}}
	runner := &fakeRunner{exits: map[string]int{"install": 0}}
	s, _ := newScheduler(t, client, runner)

	it := item("s1", 1, opts(func(o *protocol.DeploymentOptions) { o.RunAs = protocol.RunAsUser }))
	if err := s.Sync(context.Background(), []protocol.Item{it}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 0 {
		t.Fatalf("nothing should have run, got %v", got)
	}
	if len(client.runs) != 0 {
		t.Fatalf("nothing happened, so nothing should be reported, got %+v", client.runs)
	}
}

func TestFailureCountsUpAndStopsRetrying(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{Version: 1, Body: "broken"}}
	runner := &fakeRunner{exits: map[string]int{"broken": 3}}
	s, st := newScheduler(t, client, runner)

	// A recurring deployment with two retries, always due.
	o := opts(func(o *protocol.DeploymentOptions) {
		o.Frequency, o.IntervalHours, o.MaxRetries = protocol.FrequencyRecurring, 1, 2
	})
	// Each Sync is a separate check-in; the clock is fixed, so force the
	// interval by clearing the last run time between attempts.
	for i := 0; i < 4; i++ {
		if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, o)}); err != nil {
			t.Fatal(err)
		}
		local, err := st.ItemState("s1")
		if err != nil {
			t.Fatal(err)
		}
		if local.Failures < 2 {
			local.LastRunAt = now.Add(-2 * time.Hour) // make it due again
			if err := st.SetItemState("s1", local); err != nil {
				t.Fatal(err)
			}
		}
	}

	if got := len(runner.ran()); got != 2 {
		t.Fatalf("it should stop after max_retries failures, ran %d times", got)
	}
	local, _ := st.ItemState("s1")
	if local.Failures != 2 {
		t.Errorf("failures = %d, want 2", local.Failures)
	}
}

func TestOtherItemKindsAreIgnored(t *testing.T) {
	client := &fakeClient{}
	runner := &fakeRunner{}
	s, _ := newScheduler(t, client, runner)

	err := s.Sync(context.Background(), []protocol.Item{{Kind: "profile", ID: "p1", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.ran()) != 0 || client.fetches != 0 {
		t.Fatal("an unknown kind should be ignored, not fetched or run")
	}
}

func TestAFailedFetchDoesNotStopOtherScripts(t *testing.T) {
	client := &fakeClient{fetchErr: errors.New("server unreachable")}
	runner := &fakeRunner{}
	s, _ := newScheduler(t, client, runner)

	// Sync reports the problem through the log, not by failing outright.
	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil))}); err != nil {
		t.Fatalf("one bad deployment should not fail the sync: %v", err)
	}
	if len(client.runs) != 0 {
		t.Fatal("a script that could not be fetched has not run")
	}
}
