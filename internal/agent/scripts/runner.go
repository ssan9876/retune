package scripts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"retune/internal/agent/executor"
	"retune/internal/agent/state"
	"retune/internal/agent/winsession"
	"retune/internal/opsign"
	"retune/internal/protocol"
)

// Client is the part of the agent's server connection the scheduler needs.
type Client interface {
	FetchScript(ctx context.Context, id string, version int) (protocol.ScriptVersionResponse, error)
	ReportScriptRun(ctx context.Context, id string, run protocol.ScriptRun) error
}

// Scheduler runs the scripts assigned to this device and reports the results.
type Scheduler struct {
	State  *state.Store
	Client Client
	Runner executor.Runner
	Log    *slog.Logger
	Now    func() time.Time
	// Operations says whether a script must be signed by an operations key
	// before it runs.
	Operations opsign.Policy

	// mu keeps one script running at a time: two PowerShell processes fighting
	// over the same machine is rarely what an administrator meant.
	mu sync.Mutex
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Sync processes the items from one check-in, running whatever is due. Items
// of other kinds are ignored, which is how an older agent copes with a newer
// server.
func (s *Scheduler) Sync(ctx context.Context, items []protocol.Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range items {
		if item.Kind != protocol.ItemKindScript {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.syncOne(ctx, item); err != nil {
			// One bad deployment must not stop the rest.
			s.log().Warn("script deployment failed", "script_id", item.ID, "error", err)
		}
	}
	return nil
}

func (s *Scheduler) syncOne(ctx context.Context, item protocol.Item) error {
	opts, err := protocol.ParseDeploymentOptions(item.Options)
	if err != nil {
		return fmt.Errorf("options: %w", err)
	}
	st, err := s.State.ItemState(item.ID)
	if err != nil {
		return fmt.Errorf("read local state: %w", err)
	}

	decision := Decide(item.Version, opts, st, s.now())
	if !decision.Run {
		s.log().Debug("script not due", "script_id", item.ID, "reason", decision.Reason)
		return nil
	}

	version, err := s.body(ctx, item)
	if err != nil {
		return fmt.Errorf("fetch script: %w", err)
	}

	run := s.execute(ctx, version, opts)
	run.Version = item.Version

	// Record locally before reporting, so a server that cannot be reached does
	// not make the script run again on the next check-in.
	next := state.ItemState{
		Version: item.Version, LastRunAt: run.FinishedAt, LastStatus: run.Status,
	}
	if run.Status != protocol.ResultSucceeded {
		if st.Version == item.Version {
			next.Failures = st.Failures + 1
		} else {
			next.Failures = 1
		}
	}
	if err := s.State.SetItemState(item.ID, next); err != nil {
		return fmt.Errorf("record local state: %w", err)
	}
	if err := s.Client.ReportScriptRun(ctx, item.ID, run); err != nil {
		return fmt.Errorf("report run: %w", err)
	}
	return nil
}

// body returns the script contents, fetching them only when this version is
// not already cached.
func (s *Scheduler) body(ctx context.Context, item protocol.Item) (protocol.ScriptVersionResponse, error) {
	cached, found, err := s.State.CachedScript(item.ID, item.Version)
	if err != nil {
		return protocol.ScriptVersionResponse{}, err
	}
	if found {
		return cached, nil
	}
	fetched, err := s.Client.FetchScript(ctx, item.ID, item.Version)
	if err != nil {
		return protocol.ScriptVersionResponse{}, err
	}
	if err := s.State.CacheScript(item.ID, fetched); err != nil {
		return protocol.ScriptVersionResponse{}, err
	}
	return fetched, nil
}

// execute runs a deployment and returns what to report.
//
// With no detection script, the body decides. With one, detection runs first:
// exit 0 means there is nothing to do, so the body never runs. Otherwise the
// body runs and detection runs again, and that second detection decides —
// because a remediation that "succeeds" while leaving the machine
// non-compliant has not actually fixed anything.
func (s *Scheduler) execute(ctx context.Context, v protocol.ScriptVersionResponse, opts protocol.DeploymentOptions) protocol.ScriptRun {
	started := s.now()

	if s.Operations.Enforced {
		// Checked on every run, cached or not, and before detection: a
		// detection script is code too.
		if err := opsign.Verify(s.Operations.Keys, opsign.ScriptManifest(v.Body, v.DetectionBody), v.Signature); err != nil {
			refused := outcome{err: fmt.Errorf("refused: %w", err), exitCode: -1}
			return refused.report(protocol.PhaseScript, false, started, s.now())
		}
	}

	if strings.TrimSpace(v.DetectionBody) == "" {
		out := s.runOne(ctx, v.Body, opts)
		return out.report(protocol.PhaseScript, false, started, s.now())
	}

	first := s.runOne(ctx, v.DetectionBody, opts)
	if first.err == nil && first.exitCode == 0 {
		// Already in the desired state.
		return first.report(protocol.PhaseDetection, false, started, s.now())
	}
	if first.err != nil {
		return first.report(protocol.PhaseDetection, false, started, s.now())
	}

	remediation := s.runOne(ctx, v.Body, opts)
	if remediation.err != nil {
		return remediation.report(protocol.PhaseRemediation, false, started, s.now())
	}

	second := s.runOne(ctx, v.DetectionBody, opts)
	second.stdout = join(remediation.stdout, second.stdout)
	second.stderr = join(remediation.stderr, second.stderr)
	return second.report(protocol.PhaseDetection, second.exitCode == 0, started, s.now())
}

// outcome is one execution of one script body.
type outcome struct {
	exitCode int
	stdout   string
	stderr   string
	outCut   bool
	errCut   bool
	err      error
	timedOut bool
}

func (s *Scheduler) runOne(ctx context.Context, body string, opts protocol.DeploymentOptions) outcome {
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout())
	defer cancel()

	stdout, stderr := executor.NewCapped(protocol.MaxOutputBytes), executor.NewCapped(protocol.MaxOutputBytes)
	// A deployment set to run as the signed-in user runs in their session, not
	// as the service account.
	runner := s.Runner
	if opts.NeedsUserSession() {
		runner = userRunner{}
	}
	code, err := runner.RunPowerShell(runCtx, body, stdout, stderr)

	out := outcome{
		exitCode: code,
		stdout:   stdout.String(), stderr: stderr.String(),
		outCut: stdout.Truncated(), errCut: stderr.Truncated(),
	}
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		out.timedOut, out.err = true, fmt.Errorf("timed out after %s", opts.Timeout())
	case err != nil:
		out.err = err
	}
	return out
}

// report turns an execution into the run to send to the server.
func (o outcome) report(phase string, remediated bool, started, finished time.Time) protocol.ScriptRun {
	run := protocol.ScriptRun{
		Phase: phase, Remediated: remediated, ExitCode: o.exitCode,
		Stdout: o.stdout, Stderr: o.stderr,
		StdoutTruncated: o.outCut, StderrTruncated: o.errCut,
		StartedAt: started, FinishedAt: finished,
	}
	switch {
	case o.timedOut:
		run.Status, run.ExitCode, run.Error = protocol.ResultTimedOut, -1, o.err.Error()
	case o.err != nil:
		run.Status, run.ExitCode, run.Error = protocol.ResultFailed, -1, o.err.Error()
	case o.exitCode != 0:
		run.Status = protocol.ResultFailed
	default:
		run.Status = protocol.ResultSucceeded
	}
	return run
}

func join(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "\n" + b
}

// userRunner runs a script in the signed-in user's session.
type userRunner struct{}

func (userRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	return winsession.RunPowerShell(ctx, script, stdout, stderr)
}
