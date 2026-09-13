// Package apps installs and removes the applications assigned to this device,
// by driving winget.
package apps

import (
	"context"
	"errors"
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
	// passes straight through from the underlying MSI.
	RebootRequiredExit = 3010
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

// classify turns a winget exit code into what it means for a deployment. Any
// code not named above falls through to OutcomeFailed: guessing at an
// undocumented code risks calling a real failure a success, which is worse
// than the reverse.
func classify(code int) Outcome {
	switch code {
	case 0:
		return OutcomeSucceeded
	case NotInstalledExit:
		return OutcomeNotInstalled
	case RebootRequiredExit:
		return OutcomeRebootRequired
	default:
		return OutcomeFailed
	}
}

// Result is one winget invocation's outcome.
type Result struct {
	ExitCode       int
	Stdout, Stderr string
	OutCut, ErrCut bool
	Err            error
	TimedOut       bool
}

// Winget runs winget commands. The agent uses one; tests supply a fake.
type Winget interface {
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
