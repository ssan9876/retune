package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

func TestSignedRunPowerShell(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig := opsign.Sign(key, opsign.ScriptManifest("Get-Date", ""))
	runner := &fakeRunner{}
	e := &Executor{Runner: runner, Operations: opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}}}

	res := e.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell,
		protocol.RunPowerShellPayload{Script: "Get-Date", Signature: &sig}))
	if res.Status != protocol.ResultSucceeded || runner.gotScript != "Get-Date" {
		t.Fatalf("signed = %+v", res)
	}

	runner.gotScript = ""
	for name, p := range map[string]protocol.RunPowerShellPayload{
		"unsigned":         {Script: "Get-Date"},
		"another script":   {Script: "Remove-Item C:\\ -Recurse", Signature: &sig},
		"a malformed list": {Script: "Get-Date", Signature: &sig},
	} {
		ex := e
		if name == "a malformed list" {
			ex = &Executor{Runner: runner, Operations: opsign.ParsePolicy("not-a-key")}
		}
		res := ex.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell, p))
		if res.Status != protocol.ResultFailed || !strings.HasPrefix(res.Error, "refused") || runner.gotScript != "" {
			t.Errorf("%s: = %+v, ran %q", name, res, runner.gotScript)
		}
	}
}

func TestSignedWipe(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	sig := opsign.Sign(key, opsign.WipeManifest("dev-1", false, exp))
	w := &fakeWiper{}
	e := &Executor{
		Wiper: w, DeviceID: "dev-1", Now: func() time.Time { return now },
		Operations: opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}},
	}

	for name, p := range map[string]protocol.WipePayload{
		"unsigned":         {},
		"protected added":  {Protected: true, Expires: &exp, Signature: &sig},
		"no expiry":        {Signature: &sig},
		"expiry stretched": {Expires: ptr(exp.Add(24 * time.Hour)), Signature: &sig},
	} {
		res := e.Execute(context.Background(), cmd(t, protocol.CommandWipe, p))
		if res.Status != protocol.ResultFailed || !strings.HasPrefix(res.Error, "refused") {
			t.Errorf("%s: = %+v", name, res)
		}
	}
	if len(w.protected) != 0 {
		t.Fatalf("wiped on a bad order: %v", w.protected)
	}

	// Another device's order.
	other := &Executor{Wiper: w, DeviceID: "dev-2", Now: e.Now, Operations: e.Operations}
	if res := other.Execute(context.Background(), cmd(t, protocol.CommandWipe,
		protocol.WipePayload{Expires: &exp, Signature: &sig})); res.Status != protocol.ResultFailed {
		t.Fatalf("another device = %+v", res)
	}
	// Too late.
	late := &Executor{Wiper: w, DeviceID: "dev-1", Now: func() time.Time { return exp }, Operations: e.Operations}
	if res := late.Execute(context.Background(), cmd(t, protocol.CommandWipe,
		protocol.WipePayload{Expires: &exp, Signature: &sig})); res.Status != protocol.ResultFailed {
		t.Fatalf("expired = %+v", res)
	}
	if len(w.protected) != 0 {
		t.Fatalf("wiped on a bad order: %v", w.protected)
	}

	res := e.Execute(context.Background(), cmd(t, protocol.CommandWipe, protocol.WipePayload{Expires: &exp, Signature: &sig}))
	if res.Status != protocol.ResultSucceeded || len(w.protected) != 1 {
		t.Fatalf("valid order = %+v, wiped %v", res, w.protected)
	}
}

func ptr[T any](v T) *T { return &v }
