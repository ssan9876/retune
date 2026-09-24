package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestRenameComputer(t *testing.T) {
	runner, restarter := &fakeRunner{}, &fakeRestarter{}
	e := &Executor{Runner: runner, Restarter: restarter}

	res := e.Execute(context.Background(), cmd(t, protocol.CommandRenameComputer, protocol.RenameComputerPayload{Name: "LAPTOP-042"}))
	if res.Status != protocol.ResultSucceeded || runner.gotScript != "Rename-Computer -NewName 'LAPTOP-042' -Force -ErrorAction Stop" {
		t.Fatalf("result %+v, script %q", res, runner.gotScript)
	}
	if !strings.Contains(res.Stdout, "next restarts") || restarter.msg != "" {
		t.Fatalf("without restart: %q, restarted %q", res.Stdout, restarter.msg)
	}

	res = e.Execute(context.Background(), cmd(t, protocol.CommandRenameComputer, protocol.RenameComputerPayload{Name: "LAPTOP-043", Restart: true}))
	if res.Status != protocol.ResultSucceeded || restarter.delay != time.Minute || !strings.Contains(restarter.msg, "LAPTOP-043") {
		t.Fatalf("with restart: %+v, %s %q", res, restarter.delay, restarter.msg)
	}

	// A name that isn't one never reaches PowerShell, whatever the server
	// sent.
	runner.gotScript = ""
	res = e.Execute(context.Background(), cmd(t, protocol.CommandRenameComputer, protocol.RenameComputerPayload{Name: "x'; Remove-Item C:/ -Recurse; '"}))
	if res.Status != protocol.ResultFailed || runner.gotScript != "" {
		t.Fatalf("a bad name: %+v, ran %q", res, runner.gotScript)
	}
	runner.code = 1
	if res := e.Execute(context.Background(), cmd(t, protocol.CommandRenameComputer, protocol.RenameComputerPayload{Name: "PC1"})); res.Status != protocol.ResultFailed {
		t.Fatalf("a failing rename: %+v", res)
	}
}
