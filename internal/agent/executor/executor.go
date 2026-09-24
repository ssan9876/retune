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

	"retune/internal/agent/winupdate"
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
	// AfterUpdates runs once updates have been installed: forgetting the
	// last Windows Update search, so the next inventory reports afresh.
	AfterUpdates func()
	// Remote and StartShell run remote sessions.
	Remote     RemoteChannel
	StartShell ShellStarter

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
	case protocol.CommandRenameComputer:
		e.renameComputer(ctx, c.Payload, &res)
	case protocol.CommandInstallUpdates:
		e.installUpdates(ctx, c.Payload, &res)
	case protocol.CommandRemoteShell:
		e.remoteShell(ctx, c.Payload, &res)
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

// renameComputer renames the machine. The name is checked again here, as
// well as by the server: it goes into a PowerShell command line.
func (e *Executor) renameComputer(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RenameComputerPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		fail(res, fmt.Sprintf("invalid rename_computer payload: %v", err))
		return
	}
	if !protocol.ValidComputerName(p.Name) {
		fail(res, fmt.Sprintf("%q is not a computer name", p.Name))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stdout, stderr := NewCapped(protocol.MaxOutputBytes), NewCapped(protocol.MaxOutputBytes)
	code, err := e.Runner.RunPowerShell(ctx, "Rename-Computer -NewName '"+p.Name+"' -Force -ErrorAction Stop", stdout, stderr)
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	switch {
	case err != nil:
		fail(res, err.Error())
		return
	case code != 0:
		res.Status, res.ExitCode = protocol.ResultFailed, code
		return
	}
	if !p.Restart {
		res.Stdout = strings.TrimSpace(res.Stdout+"\nRenamed to "+p.Name+"; the name takes effect when the device next restarts.") + "\n"
		return
	}
	if err := e.Restarter.Restart(time.Minute, "Restarting to finish renaming this computer to "+p.Name+"."); err != nil {
		fail(res, "renamed, but the restart to finish it failed: "+err.Error())
	}
}

// installUpdates installs what Windows Update offers in scope, restarts if
// asked to and an update needs it, and reports afresh.
func (e *Executor) installUpdates(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.InstallUpdatesPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		fail(res, fmt.Sprintf("invalid install_updates payload: %v", err))
		return
	}
	if p.Restart != protocol.UpdateRestartNever && p.Restart != protocol.UpdateRestartIfRequired {
		fail(res, fmt.Sprintf("restart must be never or if_required, not %q", p.Restart))
		return
	}
	out, detail, err := winupdate.Install(ctx, e.Runner, p.Scope)
	if err != nil {
		res.Stderr = detail
		fail(res, err.Error())
		return
	}
	if e.AfterUpdates != nil {
		e.AfterUpdates()
	}
	summary, _ := json.Marshal(out)
	res.Stdout = string(summary) + "\n"
	if out.Failed > 0 {
		res.Status, res.ExitCode = protocol.ResultFailed, 1
		res.Error = fmt.Sprintf("%d of %d updates failed to install", out.Failed, out.Installed+out.Failed)
	}
	if out.RebootRequired && p.Restart == protocol.UpdateRestartIfRequired {
		if err := e.Restarter.Restart(5*time.Minute, "Restarting in five minutes to finish installing updates."); err != nil {
			fail(res, "installed, but the restart to finish failed: "+err.Error())
		}
		return
	}
	if e.RefreshInventory != nil {
		// A restart would report afresh anyway; without one, report now.
		_ = e.RefreshInventory(ctx)
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
