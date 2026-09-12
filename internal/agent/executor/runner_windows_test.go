//go:build windows

package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestPowerShellRunner(t *testing.T) {
	e := &Executor{Runner: DefaultRunner(t.TempDir()), Now: time.Now}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{
		Script:         "Write-Output 'héllo'; [Console]::Error.WriteLine('oops'); exit 3",
		TimeoutSeconds: 60,
	}))
	if res.Status != protocol.ResultFailed || res.ExitCode != 3 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Stdout, "héllo") {
		t.Fatalf("stdout = %q (UTF-8 output must survive)", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "oops") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestPowerShellRunnerTimeout(t *testing.T) {
	e := &Executor{Runner: DefaultRunner(t.TempDir()), Now: time.Now}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{
		Script: "Start-Sleep -Seconds 30", TimeoutSeconds: 2,
	}))
	if res.Status != protocol.ResultTimedOut {
		t.Fatalf("result = %+v", res)
	}
}
