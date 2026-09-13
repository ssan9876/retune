package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

type fakeRunner struct {
	code      int
	err       error
	stdout    string
	stderr    string
	block     bool
	gotScript string
}

func (f *fakeRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	f.gotScript = script
	if f.block {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	_, _ = io.WriteString(stdout, f.stdout)
	_, _ = io.WriteString(stderr, f.stderr)
	return f.code, f.err
}

type fakeRestarter struct {
	delay time.Duration
	msg   string
	err   error
}

func (f *fakeRestarter) Restart(d time.Duration, m string) error {
	f.delay, f.msg = d, m
	return f.err
}

func cmd(t *testing.T, typ string, payload any) protocol.Command {
	t.Helper()
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return protocol.Command{ID: "c1", Type: typ, Payload: raw}
}

func newExecutor(r Runner, rs Restarter, refresh func(context.Context) error) *Executor {
	if refresh == nil {
		refresh = func(context.Context) error { return nil }
	}
	return &Executor{Runner: r, Restarter: rs, RefreshInventory: refresh, Now: time.Now}
}

func TestRunPowerShell(t *testing.T) {
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		r := &fakeRunner{stdout: "hello", stderr: "note"}
		res := newExecutor(r, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "Get-Date", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultSucceeded || res.ExitCode != 0 || res.Stdout != "hello" || res.Stderr != "note" {
			t.Fatalf("result = %+v", res)
		}
		if r.gotScript != "Get-Date" {
			t.Fatalf("script = %q", r.gotScript)
		}
		if res.FinishedAt.Before(res.StartedAt) {
			t.Fatal("FinishedAt must not precede StartedAt")
		}
	})
	t.Run("non-zero exit", func(t *testing.T) {
		res := newExecutor(&fakeRunner{code: 3}, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "exit 3", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultFailed || res.ExitCode != 3 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("runner error", func(t *testing.T) {
		res := newExecutor(&fakeRunner{err: errors.New("powershell missing")}, nil, nil).Execute(ctx,
			cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "x", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultFailed || res.ExitCode != -1 || !strings.Contains(res.Error, "powershell missing") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		res := newExecutor(&fakeRunner{block: true}, nil, nil).Execute(ctx,
			cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "sleep", TimeoutSeconds: 1}))
		if res.Status != protocol.ResultTimedOut || res.ExitCode != -1 || !strings.Contains(res.Error, "timed out") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("output is capped", func(t *testing.T) {
		r := &fakeRunner{stdout: strings.Repeat("x", protocol.MaxOutputBytes+10)}
		res := newExecutor(r, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "big", TimeoutSeconds: 30}))
		if len(res.Stdout) != protocol.MaxOutputBytes || !res.StdoutTruncated {
			t.Fatalf("stdout len = %d truncated = %v", len(res.Stdout), res.StdoutTruncated)
		}
	})
	t.Run("invalid payload", func(t *testing.T) {
		res := newExecutor(&fakeRunner{}, nil, nil).Execute(ctx, protocol.Command{ID: "c1", Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{`)})
		if res.Status != protocol.ResultFailed || res.Error == "" {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("empty script", func(t *testing.T) {
		res := newExecutor(&fakeRunner{}, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{}))
		if res.Status != protocol.ResultFailed {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestRestartAndRefresh(t *testing.T) {
	ctx := context.Background()
	rs := &fakeRestarter{}
	res := newExecutor(&fakeRunner{}, rs, nil).Execute(ctx, cmd(t, protocol.CommandRestart,
		protocol.RestartPayload{DelaySeconds: 30, Message: "patching"}))
	if res.Status != protocol.ResultSucceeded || rs.delay != 30*time.Second || rs.msg != "patching" {
		t.Fatalf("result = %+v restarter = %+v", res, rs)
	}

	failing := &fakeRestarter{err: errors.New("access denied")}
	res = newExecutor(&fakeRunner{}, failing, nil).Execute(ctx, cmd(t, protocol.CommandRestart, protocol.RestartPayload{}))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "access denied") {
		t.Fatalf("result = %+v", res)
	}

	called := false
	res = newExecutor(&fakeRunner{}, rs, func(context.Context) error { called = true; return nil }).
		Execute(ctx, cmd(t, protocol.CommandRefreshInventory, nil))
	if res.Status != protocol.ResultSucceeded || !called {
		t.Fatalf("result = %+v called = %v", res, called)
	}

	res = newExecutor(&fakeRunner{}, rs, func(context.Context) error { return errors.New("wmi unavailable") }).
		Execute(ctx, cmd(t, protocol.CommandRefreshInventory, nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "wmi unavailable") {
		t.Fatalf("result = %+v", res)
	}
}

func TestUnknownType(t *testing.T) {
	res := newExecutor(&fakeRunner{}, &fakeRestarter{}, nil).Execute(context.Background(), cmd(t, "fly_to_moon", nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "unsupported") {
		t.Fatalf("result = %+v", res)
	}
}

func TestCappedWriter(t *testing.T) {
	c := NewCapped(8)
	if _, err := c.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("6789")); err != nil {
		t.Fatal(err)
	}
	if c.String() != "12345678" || !c.Truncated() {
		t.Fatalf("capped = %q truncated = %v", c.String(), c.Truncated())
	}

	invalid := NewCapped(16)
	if _, err := invalid.Write([]byte{0xff, 'a'}); err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsRune(invalid.String(), '�') || !strings.HasSuffix(invalid.String(), "a") {
		t.Fatalf("invalid UTF-8 not repaired: %q", invalid.String())
	}
}
