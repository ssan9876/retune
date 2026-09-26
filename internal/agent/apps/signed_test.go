package apps_test

import (
	"context"
	"strings"
	"testing"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

func TestSignedApps(t *testing.T) {
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	policy := opsign.Policy{Enforced: true, Keys: []release.PublicKey{key.Public()}}
	sevenZip := protocol.AppVersionResponse{Version: 1, PackageID: "7zip.7zip", Scope: "machine"}
	signed := func(by release.PrivateKey, v protocol.AppVersionResponse) *opsign.Signature {
		s := opsign.Sign(by, v.Definition().Manifest())
		return &s
	}
	with := func(v protocol.AppVersionResponse, edit func(*protocol.AppVersionResponse)) protocol.AppVersionResponse {
		edit(&v)
		return v
	}

	cases := map[string]struct {
		version  protocol.AppVersionResponse
		policy   opsign.Policy
		installs bool
	}{
		"signed": {with(sevenZip, func(v *protocol.AppVersionResponse) { v.Signature = signed(key, sevenZip) }), policy, true},
		// The server leaves scope out for an older version; it means machine,
		// and the signature must still match.
		"signed, scope left out": {with(sevenZip, func(v *protocol.AppVersionResponse) {
			v.Scope, v.Signature = "", signed(key, sevenZip)
		}), policy, true},
		"unsigned":        {sevenZip, policy, false},
		"unsigned, lax":   {sevenZip, opsign.Policy{}, true},
		"untrusted key":   {with(sevenZip, func(v *protocol.AppVersionResponse) { v.Signature = signed(other, sevenZip) }), policy, false},
		"package swapped": {with(sevenZip, func(v *protocol.AppVersionResponse) { v.PackageID, v.Signature = "Evil.Tool", signed(key, sevenZip) }), policy, false},
		// Install arguments reach the installer, so they are covered too.
		"arguments added": {with(sevenZip, func(v *protocol.AppVersionResponse) {
			v.InstallArgs, v.Signature = "--override /S & calc.exe", signed(key, sevenZip)
		}), policy, false},
		"no trusted keys": {with(sevenZip, func(v *protocol.AppVersionResponse) { v.Signature = signed(key, sevenZip) }),
			opsign.Policy{Enforced: true}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{version: c.version}
			w := &fakeWinget{}
			s, _ := newSyncer(t, client, w)
			s.Operations = c.policy
			if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
				t.Fatal(err)
			}
			installed := strings.Contains(strings.Join(w.ran(), ","), "install")
			if installed != c.installs {
				t.Fatalf("ran %v, want installs=%v", w.ran(), c.installs)
			}
			if c.installs {
				return
			}
			// A refused app runs nothing at all, not even detection, and says
			// why.
			if len(w.ran()) != 0 {
				t.Errorf("a refused app should run nothing, ran %v", w.ran())
			}
			if len(client.results) != 1 || client.results[0].Status != protocol.ResultFailed ||
				!strings.Contains(client.results[0].Detail, "refused") {
				t.Fatalf("reported %+v", client.results)
			}
			// Once per version, like any other reason it can't be installed.
			if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
				t.Fatal(err)
			}
			if len(client.results) != 1 {
				t.Errorf("the refusal should be reported once, got %d reports", len(client.results))
			}
		})
	}
}

// An uploaded package's signature covers everything the agent acts on: the
// file's hash, both command lines, the exit codes and the detection rule.
func TestPackageManifestCoversEveryField(t *testing.T) {
	base := protocol.AppDefinition{
		Source: protocol.AppSourcePackage, InstallerType: protocol.InstallerMSI, FileName: "setup.msi",
		FileSHA256: strings.Repeat("ab", 32), InstallArgs: "/qn", UninstallCommand: "msiexec /x {X} /qn",
		SuccessExitCodes: []int{0}, UninstallPrevious: true,
		Detection: &protocol.DetectionRule{Type: protocol.DetectFile, Path: `%ProgramFiles%\App\app.exe`},
	}
	want := string(base.Manifest())
	changes := map[string]func(*protocol.AppDefinition){
		"hash":              func(d *protocol.AppDefinition) { d.FileSHA256 = strings.Repeat("cd", 32) },
		"install args":      func(d *protocol.AppDefinition) { d.InstallArgs = "/qn EVIL=1" },
		"uninstall command": func(d *protocol.AppDefinition) { d.UninstallCommand = "cmd /c del c:\\" },
		"exit codes":        func(d *protocol.AppDefinition) { d.SuccessExitCodes = []int{0, 1} },
		"detection": func(d *protocol.AppDefinition) {
			d.Detection = &protocol.DetectionRule{Type: protocol.DetectFile, Path: "C:\\x"}
		},
		"uninstall first": func(d *protocol.AppDefinition) { d.UninstallPrevious = false },
		"installer type":  func(d *protocol.AppDefinition) { d.InstallerType = protocol.InstallerEXE },
		"file name":       func(d *protocol.AppDefinition) { d.FileName = "other.msi" },
	}
	for name, change := range changes {
		d := base
		change(&d)
		if string(d.Manifest()) == want {
			t.Errorf("changing the %s left the manifest the same", name)
		}
	}
	// What the server fills in doesn't change it: a hash in capitals, and
	// no exit codes meaning the defaults.
	d := base
	d.FileSHA256 = strings.ToUpper(d.FileSHA256)
	if string(d.Manifest()) != want {
		t.Error("the hash's case should not matter")
	}
	d = base
	d.SuccessExitCodes = nil
	e := base
	e.SuccessExitCodes = protocol.DefaultSuccessExitCodes()
	if string(d.Manifest()) != string(e.Manifest()) {
		t.Error("no exit codes should sign as the default ones")
	}
}
