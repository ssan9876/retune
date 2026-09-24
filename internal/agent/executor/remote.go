package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"retune/internal/protocol"
)

// RemoteChannel carries a remote session to and from the server.
type RemoteChannel interface {
	// RemoteInput waits a while for what the administrator typed after seq.
	RemoteInput(ctx context.Context, sessionID string, after int64) (protocol.RemoteInputResponse, error)
	RemoteOutput(ctx context.Context, sessionID, stream, data string) error
	RemoteEnd(ctx context.Context, sessionID, reason string) error
}

// Shell is a running interactive shell.
type Shell struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	Stderr io.Reader
	// Wait returns when the shell exits.
	Wait func() error
	// Kill ends it.
	Kill func()
}

// ShellStarter starts the shell a remote session types into.
type ShellStarter func(ctx context.Context) (*Shell, error)

// DefaultShell is Windows PowerShell reading commands from its input, as
// SYSTEM - the agent's own account.
func DefaultShell(ctx context.Context) (*Shell, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("remote sessions are only supported on Windows")
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Shell{
		Stdin: stdin, Stdout: stdout, Stderr: stderr, Wait: cmd.Wait,
		Kill: func() { _ = cmd.Process.Kill() },
	}, nil
}

// remoteLimits are how long a session may idle and last; tests shorten them.
var remoteLimits = struct{ idle, max time.Duration }{protocol.RemoteIdleTimeout, protocol.RemoteMaxDuration}

// remoteShell runs one remote session: the administrator's input goes to
// the shell, and everything it writes comes back, until the session is
// ended from the console, the shell exits, nobody types for a while, or it
// reaches its time limit.
func (e *Executor) remoteShell(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RemoteShellPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.SessionID == "" {
		fail(res, "invalid remote_shell payload")
		return
	}
	end := func(reason string) {
		if e.Remote != nil {
			endCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = e.Remote.RemoteEnd(endCtx, p.SessionID, reason)
		}
	}
	// A device built to run only signed code runs no unsigned commands, and
	// a remote shell is nothing but.
	if e.Operations.Enforced {
		end("this device runs only signed code, so it refuses remote shells")
		fail(res, "refused: this device runs only signed code")
		return
	}
	if e.Remote == nil || e.StartShell == nil {
		end("this agent can't run remote sessions")
		fail(res, "remote sessions aren't available on this agent")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, remoteLimits.max)
	defer cancel()
	sh, err := e.StartShell(ctx)
	if err != nil {
		end("the shell didn't start: " + err.Error())
		fail(res, "starting the shell: "+err.Error())
		return
	}

	var pumps sync.WaitGroup
	for stream, r := range map[string]io.Reader{protocol.RemoteStreamOut: sh.Stdout, protocol.RemoteStreamErr: sh.Stderr} {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			e.pumpRemote(ctx, p.SessionID, stream, r)
		}()
	}
	exited := make(chan struct{})
	go func() {
		_ = sh.Wait()
		close(exited)
	}()
	inputDone := make(chan string, 1)
	go func() { inputDone <- e.relayInput(ctx, p.SessionID, sh.Stdin) }()

	var reason string
	select {
	case <-exited:
		reason = "the shell exited"
	case reason = <-inputDone:
	}
	cancel()
	sh.Kill()
	_ = sh.Stdin.Close()
	pumps.Wait()
	end(reason)
	res.Stdout = "remote session ended: " + reason + "\n"
}

// relayInput copies the administrator's input to the shell until the
// session ends, and says why it did.
func (e *Executor) relayInput(ctx context.Context, sessionID string, stdin io.Writer) string {
	var after int64
	lastInput := e.now()
	failures := 0
	for {
		if ctx.Err() != nil {
			return "the session reached its time limit"
		}
		if e.now().Sub(lastInput) > remoteLimits.idle {
			return "nothing was typed for fifteen minutes"
		}
		resp, err := e.Remote.RemoteInput(ctx, sessionID, after)
		if err != nil {
			if ctx.Err() != nil {
				return "the session reached its time limit"
			}
			if failures++; failures >= 5 {
				return "the server couldn't be reached: " + err.Error()
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			continue
		}
		failures = 0
		for _, c := range resp.Chunks {
			if _, err := io.WriteString(stdin, c.Data); err != nil {
				return "the shell stopped reading its input"
			}
			after, lastInput = c.Seq, e.now()
		}
		if resp.Ended {
			return "ended from the console"
		}
	}
}

// pumpRemote sends what the shell writes to one stream back to the server.
func (e *Executor) pumpRemote(ctx context.Context, sessionID, stream string, r io.Reader) {
	buf := make([]byte, 16<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := strings.ToValidUTF8(string(buf[:n]), "?")
			// Output that can't be delivered is lost, not retried: the shell
			// keeps running, and the next chunk may get through.
			sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = e.Remote.RemoteOutput(sendCtx, sessionID, stream, data)
			cancel()
		}
		if err != nil {
			return
		}
	}
}
