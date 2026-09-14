// Package apps installs and removes the applications assigned to this device,
// by driving winget.
package apps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"retune/internal/protocol"
)

// Exit codes worth naming. Zero and NotInstalledExit were observed on a real
// machine; the reboot code is Windows Installer's standard one. Anything not
// named here is a plain failure, which is the safe default: a machine wrongly
// reported failed gets looked at, one wrongly reported succeeded does not.
const (
	// NotInstalledExit is APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND. It is
	// how `winget list` says the package is absent, and is the detection
	// signal rather than an error.
	NotInstalledExit = -1978335212
	// RebootRequiredExit means the install worked and Windows wants a restart.
	// It is Windows Installer's own ERROR_SUCCESS_REBOOT_REQUIRED, which winget
	// passes straight through from the underlying MSI. Unlike the two
	// constants below, this one is a small positive number, not a DWORD with
	// its high bit set, so it round-trips through int32(uint32(x)) unchanged
	// and was never affected by the bug normalizeExitCode fixes.
	RebootRequiredExit = 3010
	// WingetRebootRequiredExit is winget's own
	// APPINSTALLER_CLI_ERROR_INSTALL_REBOOT_REQUIRED_TO_FINISH, returned by
	// winget itself (rather than passed through from the MSI) when a reboot
	// is needed to finish. It lives in the same high-bit HRESULT-derived
	// range as NotInstalledExit and so has exactly the same signed/unsigned
	// mismatch if compared without normalizing first.
	WingetRebootRequiredExit = -1978334967
)

// Outcome is what an exit code means for a deployment, once the handful of
// codes that carry special meaning are told apart from an ordinary failure.
type Outcome int

const (
	OutcomeSucceeded Outcome = iota
	OutcomeNotInstalled
	OutcomeRebootRequired
	OutcomeFailed
)

// normalizeExitCode converts a raw process exit code to the signed 32-bit
// value that Microsoft's documentation, winget's own source, and PowerShell's
// $LASTEXITCODE all use.
//
// Windows exit statuses are DWORDs (unsigned 32-bit values). Go's
// (*os.ProcessState).ExitCode() surfaces that DWORD as a positive int on
// Windows, but the named constants above are written in signed form, because
// that is how Windows documents and displays them. -1978335212 and
// 2316632084 are bit-for-bit the same DWORD; a raw `==` between the signed
// constant and the value Go actually returns silently never matches. That
// is precisely how this package shipped broken: every unit test compared
// classify against the signed constant directly and never against the value
// a real run produces, so all of them passed while every real detection was
// misclassified as a failure and the agent installed nothing, on every
// device, forever.
//
// Do not remove this conversion because it "looks redundant" with the
// constants already being int-typed — the whole bug was that the types lined
// up while the values didn't.
func normalizeExitCode(code int) int32 {
	return int32(uint32(code))
}

// classify turns a winget exit code into what it means for a deployment. Any
// code not named above falls through to OutcomeFailed: guessing at an
// undocumented code risks calling a real failure a success, which is worse
// than the reverse.
func classify(code int) Outcome {
	switch normalizeExitCode(code) {
	case 0:
		return OutcomeSucceeded
	case NotInstalledExit:
		return OutcomeNotInstalled
	case RebootRequiredExit, WingetRebootRequiredExit:
		return OutcomeRebootRequired
	default:
		return OutcomeFailed
	}
}

// detectResult turns a `winget list` exit code into a detection outcome.
// OutcomeNotInstalled is a successful detection whose answer is "absent", so
// it returns a nil error; any other non-success is a failed detection, not
// an answer, and returns an error naming the exit code. Folding the two
// together — as if any non-zero code just meant "not installed" — would make
// a caller reinstall the package on every cycle during an outage that has
// nothing to do with the package itself.
func detectResult(code int) (installed bool, err error) {
	switch classify(code) {
	case OutcomeSucceeded:
		return true, nil
	case OutcomeNotInstalled:
		return false, nil
	default:
		// Reported in normalized (signed) form, matching NotInstalledExit and
		// friends above, so a code that shows up here can be looked up
		// directly against the documented constant instead of needing a
		// mental (or actual) unsigned-to-signed conversion first.
		return false, fmt.Errorf("winget list failed with exit code %d", normalizeExitCode(code))
	}
}

// Result is one winget invocation's outcome.
type Result struct {
	// ExitCode is always normalized (see normalizeExitCode): the signed
	// 32-bit form, matching NotInstalledExit and the other named constants,
	// not the raw positive DWORD Go's exec package hands back on Windows.
	// Keeping one representation everywhere means a code logged here, or
	// reported to the server, can be compared against the documented
	// constants by eye instead of silently being the wrong sign.
	ExitCode       int
	Stdout, Stderr string
	OutCut, ErrCut bool
	Err            error
	TimedOut       bool
}

// Winget runs winget commands. The agent uses one; tests supply a fake.
type Winget interface {
	// Detect reports whether packageID is installed. A caller MUST check
	// Result.Err before trusting installed: a failed detection (winget
	// broken, source unreachable, network down) is not the same as an
	// absent package. Both surface as installed == false, but only a clean
	// "absent" leaves Err nil — treating a failure as "absent" makes the
	// agent reinstall the software on every single cycle for as long as the
	// outage lasts.
	Detect(ctx context.Context, packageID string) (installed bool, version string, r Result)
	Install(ctx context.Context, v protocol.AppVersionResponse) Result
	Uninstall(ctx context.Context, packageID string) Result
}

// ErrNoAppInstaller is returned by New when this machine cannot run winget at
// all, whether because App Installer is missing or because this is not
// Windows.
var ErrNoAppInstaller = errors.New("this machine has no App Installer, so winget cannot run")

// baseArgs are on every invocation. --source winget keeps the Store out of
// it: msstore prompts for an agreement and needs the machine's region sent
// upstream, and cannot be installed from silently. --disable-interactivity
// backs that up so nothing ever waits on a person who is not there.
func baseArgs() []string {
	return []string{"--exact", "--source", "winget",
		"--disable-interactivity", "--accept-source-agreements"}
}

func detectArgs(packageID string) []string {
	return append([]string{"list", "--id", packageID}, baseArgs()...)
}

func installArgs(v protocol.AppVersionResponse) []string {
	args := append([]string{"install", "--id", v.PackageID}, baseArgs()...)
	if strings.TrimSpace(v.PinnedVersion) != "" {
		args = append(args, "--version", v.PinnedVersion)
	}
	args = append(args, "--scope", v.Scope, "--silent", "--accept-package-agreements")
	// Anything the author added goes last, so it reaches the installer rather
	// than being read as a winget flag.
	if extra := strings.Fields(v.InstallArgs); len(extra) > 0 {
		args = append(args, extra...)
	}
	return args
}

func uninstallArgs(packageID string) []string {
	return append([]string{"uninstall", "--id", packageID, "--silent"}, baseArgs()...)
}

// installedVersion scans a `winget list` table for the row naming packageID
// and returns the field after it, which is the Version column. Absent output
// (nothing installed) yields "" rather than a false match.
func installedVersion(stdout, packageID string) string {
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == packageID && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}
