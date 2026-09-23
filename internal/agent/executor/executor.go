// Package executor runs the commands the server sends.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
)

// Runner runs a PowerShell script, streaming its output.
type Runner interface {
	RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (exitCode int, err error)
}

// Restarter schedules a reboot.
type Restarter interface {
	Restart(delay time.Duration, message string) error
}

// Executor turns commands into results. It never returns an error: every
// outcome is reported as a CommandResult.
type Executor struct {
	Runner           Runner
	Restarter        Restarter
	RefreshInventory func(ctx context.Context) error
	Now              func() time.Time

	// The remote actions. Each is optional: one left nil fails its command
	// with a plain reason rather than panicking.
	Locker   Locker
	Wiper    Wiper
	Uploader ArtifactUploader
	Logs     LogSources
	// Passwords and Escrower rotate local admin passwords.
	Passwords PasswordSetter
	Escrower  PasswordEscrower

	// Operations says whether run_powershell and wipe must be signed by an
	// operations key; DeviceID is what a signed wipe must name.
	Operations opsign.Policy
	DeviceID   string
}

// Execute runs one command.
func (e *Executor) Execute(ctx context.Context, c protocol.Command) protocol.CommandResult {
	res := protocol.CommandResult{Status: protocol.ResultSucceeded, StartedAt: e.now()}
	switch c.Type {
	case protocol.CommandRunPowerShell:
		e.runPowerShell(ctx, c.Payload, &res)
	case protocol.CommandRestart:
		e.restart(c.Payload, &res)
	case protocol.CommandRefreshInventory:
		if err := e.RefreshInventory(ctx); err != nil {
			fail(&res, fmt.Sprintf("refreshing inventory: %v", err))
		}
	case protocol.CommandLock:
		e.lock(ctx, &res)
	case protocol.CommandCollectLogs:
		e.collectLogs(ctx, c, &res)
	case protocol.CommandWipe:
		e.wipe(ctx, c.Payload, &res)
	case protocol.CommandRotateAdminPassword:
		e.rotateAdminPassword(ctx, c, &res)
	default:
		fail(&res, fmt.Sprintf("unsupported command type %q", c.Type))
	}
	res.FinishedAt = e.now()
	return res
}

func (e *Executor) runPowerShell(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RunPowerShellPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		fail(res, fmt.Sprintf("invalid run_powershell payload: %v", err))
		return
	}
	if strings.TrimSpace(p.Script) == "" {
		fail(res, "run_powershell payload has no script")
		return
	}
	if e.Operations.Enforced {
		if err := opsign.Verify(e.Operations.Keys, opsign.ScriptManifest(p.Script, ""), p.Signature); err != nil {
			fail(res, "refused: "+err.Error())
			return
		}
	}
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr := NewCapped(protocol.MaxOutputBytes), NewCapped(protocol.MaxOutputBytes)
	code, err := e.Runner.RunPowerShell(ctx, p.Script, stdout, stderr)
	res.Stdout, res.StdoutTruncated = stdout.String(), stdout.Truncated()
	res.Stderr, res.StderrTruncated = stderr.String(), stderr.Truncated()

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status, res.ExitCode = protocol.ResultTimedOut, -1
		res.Error = fmt.Sprintf("timed out after %s", timeout)
	case err != nil:
		fail(res, err.Error())
	case code != 0:
		res.Status, res.ExitCode = protocol.ResultFailed, code
	default:
		res.ExitCode = 0
	}
}

func (e *Executor) restart(raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RestartPayload
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &p); err != nil {
			fail(res, fmt.Sprintf("invalid restart payload: %v", err))
			return
		}
	}
	if err := e.Restarter.Restart(time.Duration(p.DelaySeconds)*time.Second, p.Message); err != nil {
		fail(res, err.Error())
	}
}

func (e *Executor) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func fail(res *protocol.CommandResult, msg string) {
	res.Status, res.ExitCode, res.Error = protocol.ResultFailed, -1, msg
}
