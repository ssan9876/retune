package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestInstallUpdates(t *testing.T) {
	runner := &fakeRunner{stdout: `{"installed":2,"failed":0,"reboot_required":true,"titles":["a","b"]}`}
	restarter := &fakeRestarter{}
	invalidated, refreshed := 0, 0
	e := &Executor{Runner: runner, Restarter: restarter, AfterUpdates: func() { invalidated++ },
		RefreshInventory: func(context.Context) error { refreshed++; return nil }}

	// Needs a restart, and was told to: restarts, and skips the refresh the
	// restart makes pointless.
	res := e.Execute(context.Background(), cmd(t, protocol.CommandInstallUpdates,
		protocol.InstallUpdatesPayload{Scope: protocol.UpdatesSecurity, Restart: protocol.UpdateRestartIfRequired}))
	if res.Status != protocol.ResultSucceeded || restarter.delay != 5*time.Minute || invalidated != 1 || refreshed != 0 {
		t.Fatalf("result %+v, restart %s, invalidated %d, refreshed %d", res, restarter.delay, invalidated, refreshed)
	}
	if !strings.Contains(res.Stdout, `"installed":2`) || !strings.Contains(runner.gotScript, "$securityOnly = $true") {
		t.Fatalf("stdout %q", res.Stdout)
	}

	// Told never to restart: reports afresh instead.
	restarter.delay = 0
	res = e.Execute(context.Background(), cmd(t, protocol.CommandInstallUpdates,
		protocol.InstallUpdatesPayload{Scope: protocol.UpdatesAll, Restart: protocol.UpdateRestartNever}))
	if res.Status != protocol.ResultSucceeded || restarter.delay != 0 || refreshed != 1 {
		t.Fatalf("never restart: %+v, refreshed %d", res, refreshed)
	}

	// Some failed.
	runner.stdout = `{"installed":1,"failed":1,"reboot_required":false}`
	if res := e.Execute(context.Background(), cmd(t, protocol.CommandInstallUpdates,
		protocol.InstallUpdatesPayload{Scope: protocol.UpdatesAll, Restart: protocol.UpdateRestartNever})); res.Status != protocol.ResultFailed ||
		!strings.Contains(res.Error, "1 of 2") {
		t.Fatalf("partial failure: %+v", res)
	}

	// Bad payloads never reach PowerShell.
	runner.gotScript = ""
	for _, p := range []protocol.InstallUpdatesPayload{{Scope: "drivers", Restart: "never"}, {Scope: "all", Restart: "whenever"}} {
		if res := e.Execute(context.Background(), cmd(t, protocol.CommandInstallUpdates, p)); res.Status != protocol.ResultFailed || runner.gotScript != "" {
			t.Fatalf("%+v: %+v, ran %q", p, res, runner.gotScript)
		}
	}
	runner.err = errors.New("boom")
	if res := e.Execute(context.Background(), cmd(t, protocol.CommandInstallUpdates,
		protocol.InstallUpdatesPayload{Scope: protocol.UpdatesAll, Restart: protocol.UpdateRestartNever})); res.Status != protocol.ResultFailed {
		t.Fatalf("a runner error: %+v", res)
	}
}
