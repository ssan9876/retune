package apps

import (
	"slices"
	"strings"
	"testing"

	"retune/internal/protocol"
)

// The msstore source prompts for an agreement and sends the machine's region
// upstream, so every invocation pins the winget source.
func TestEveryCommandPinsTheSource(t *testing.T) {
	cases := map[string][]string{
		"detect":    detectArgs("7zip.7zip"),
		"install":   installArgs(protocol.AppVersionResponse{PackageID: "7zip.7zip", Scope: "machine"}),
		"uninstall": uninstallArgs("7zip.7zip"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if !slices.Contains(args, "--source") || !slices.Contains(args, "winget") {
				t.Errorf("%v should pin --source winget", args)
			}
			if !slices.Contains(args, "--exact") {
				t.Errorf("%v should match the id exactly, or a search could install the wrong thing", args)
			}
			if !slices.Contains(args, "--disable-interactivity") {
				t.Errorf("%v runs unattended and must never wait for a person", args)
			}
		})
	}
}

// An install is silent, machine-wide, and pins the version when one is asked
// for. Extra arguments the author supplied come last, so they reach the
// installer rather than winget.
func TestInstallArgs(t *testing.T) {
	args := installArgs(protocol.AppVersionResponse{
		PackageID: "7zip.7zip", PinnedVersion: "26.03", Scope: "machine",
		InstallArgs: "/NORESTART",
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"install", "--id 7zip.7zip", "--version 26.03", "--scope machine",
		"--silent", "--accept-package-agreements",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q should contain %q", joined, want)
		}
	}
	if args[len(args)-1] != "/NORESTART" {
		t.Errorf("author arguments belong last, got %v", args)
	}

	// With nothing pinned, no --version is passed at all: winget then
	// installs whatever is current, which is what an unpinned app means.
	plain := installArgs(protocol.AppVersionResponse{PackageID: "7zip.7zip", Scope: "machine"})
	if slices.Contains(plain, "--version") {
		t.Errorf("an unpinned app should not pin a version, got %v", plain)
	}
}

// "Not installed" is a specific exit code, not empty output. Treating it as a
// failure would make every first install look broken.
func TestClassify(t *testing.T) {
	cases := map[int]Outcome{
		0:                  OutcomeSucceeded,
		NotInstalledExit:   OutcomeNotInstalled,
		RebootRequiredExit: OutcomeRebootRequired,
		1:                  OutcomeFailed,
		-1:                 OutcomeFailed,
	}
	for code, want := range cases {
		if got := classify(code); got != want {
			t.Errorf("classify(%d) = %v, want %v", code, got, want)
		}
	}
}

// classify must treat the signed constant and the unsigned DWORD Go's
// exec package actually returns on Windows as the same status: they are
// bit-for-bit the same exit code, just read as different Go integer types.
// This is the exact case the old tests never exercised — they only ever
// passed the signed constant in, never the value a real run on Windows
// produces — which is how the "not installed" detection silently stopped
// working on every device while every unit test kept passing.
func TestClassifyNormalizesUnsignedExitCodes(t *testing.T) {
	cases := map[int]Outcome{
		NotInstalledExit:         OutcomeNotInstalled,
		2316632084:               OutcomeNotInstalled, // NotInstalledExit as an unsigned DWORD
		WingetRebootRequiredExit: OutcomeRebootRequired,
		2316632329:               OutcomeRebootRequired, // WingetRebootRequiredExit as an unsigned DWORD
	}
	for code, want := range cases {
		if got := classify(code); got != want {
			t.Errorf("classify(%d) = %v, want %v", code, got, want)
		}
	}
}

// A failed detection is not the same as an absent package. Folding a plain
// failure exit code into "not installed" would make the agent reinstall the
// software on every cycle during an outage that has nothing to do with the
// package itself, so a failure must come back with an error the caller can
// check before trusting the bool.
func TestDetectResult(t *testing.T) {
	if installed, err := detectResult(NotInstalledExit); installed || err != nil {
		t.Errorf("detectResult(NotInstalledExit) = (%v, %v), want (false, nil)", installed, err)
	}
	if installed, err := detectResult(0); !installed || err != nil {
		t.Errorf("detectResult(0) = (%v, %v), want (true, nil)", installed, err)
	}
	if installed, err := detectResult(1); installed || err == nil {
		t.Errorf("detectResult(1) = (%v, %v), want (false, non-nil error)", installed, err)
	}
}

// detectResult is what Winget.Detect actually calls with the exit code
// exitErr.ExitCode() hands back on Windows: an unsigned DWORD, not the
// signed constant. This proves the "absent, cleanly" path — the exact path
// that shipped broken — against that real value, not just against
// NotInstalledExit itself.
func TestDetectResultUnsignedNotInstalled(t *testing.T) {
	if installed, err := detectResult(2316632084); installed || err != nil {
		t.Errorf("detectResult(2316632084) = (%v, %v), want (false, nil)", installed, err)
	}
}

// winget prints a table; the installed version is the column after the id.
func TestInstalledVersion(t *testing.T) {
	const out = `
Name                 Id          Version
-----------------------------------------
7-Zip                7zip.7zip   26.03
`
	if got := installedVersion(out, "7zip.7zip"); got != "26.03" {
		t.Errorf("installedVersion = %q, want 26.03", got)
	}
	if got := installedVersion("No installed package found matching input criteria.", "7zip.7zip"); got != "" {
		t.Errorf("nothing installed means no version, got %q", got)
	}
}
