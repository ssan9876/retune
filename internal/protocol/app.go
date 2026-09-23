package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ItemKindApp is the assignment kind for application deployments.
const ItemKindApp = "app"

// What an assignment asks for. Removing software is a deliberate instruction,
// not a consequence of a device leaving a group.
const (
	IntentInstall   = "install"
	IntentUninstall = "uninstall"
)

// ScopeMachine installs for every user of the machine. It is the only scope:
// the agent runs as LocalSystem, so a per-user install would land in the
// system account's profile rather than any real person's.
const ScopeMachine = "machine"

// Limits on what an administrator may ask for. Installs are far slower than
// scripts, so the floor is higher and the ceiling is four hours.
const (
	MinAppTimeoutSeconds = 60
	MaxAppTimeoutSeconds = 14400
)

// AppOptions are the per-assignment settings of an app deployment. They travel
// to the agent on check-in, which is why they live here.
type AppOptions struct {
	Intent         string `json:"intent"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// DefaultAppOptions are applied to anything the caller leaves out.
func DefaultAppOptions() AppOptions {
	return AppOptions{Intent: IntentInstall, TimeoutSeconds: 900}
}

// Timeout is the limit on one winget invocation.
func (o AppOptions) Timeout() time.Duration {
	return time.Duration(o.TimeoutSeconds) * time.Second
}

// ParseAppOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseAppOptions(raw []byte) (AppOptions, error) {
	o := DefaultAppOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return AppOptions{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return AppOptions{}, err
	}
	return o, nil
}

func (o AppOptions) validate() error {
	switch o.Intent {
	case IntentInstall, IntentUninstall:
	default:
		return fmt.Errorf("%w: intent must be %q or %q, not %q",
			ErrBadOptions, IntentInstall, IntentUninstall, o.Intent)
	}
	if o.TimeoutSeconds < MinAppTimeoutSeconds || o.TimeoutSeconds > MaxAppTimeoutSeconds {
		return fmt.Errorf("%w: timeout_seconds must be between %d and %d",
			ErrBadOptions, MinAppTimeoutSeconds, MaxAppTimeoutSeconds)
	}
	return nil
}

// Marshal returns the canonical JSON for storing on an assignment.
func (o AppOptions) Marshal() ([]byte, error) { return json.Marshal(o) }

// AppVersionResponse is the body of
// GET /api/agent/v1/apps/{id}/versions/{version}.
type AppVersionResponse struct {
	Version int `json:"version"`
	// PackageID is the winget package, such as "7zip.7zip".
	PackageID string `json:"package_id"`
	// PinnedVersion is an exact version, or empty for whatever is current when
	// it is first installed.
	PinnedVersion string `json:"pinned_version"`
	Scope         string `json:"scope"`
	// InstallArgs are passed through to the installer, usually empty.
	InstallArgs string `json:"install_args"`
	Hash        string `json:"hash"`

	// Source is AppSourceWinget (or empty, from an older server) or
	// AppSourcePackage. The fields below are for packages only.
	Source        string `json:"source,omitempty"`
	InstallerType string `json:"installer_type,omitempty"`
	FileName      string `json:"file_name,omitempty"`
	FileSHA256    string `json:"file_sha256,omitempty"`
	FileSize      int64  `json:"file_size,omitempty"`
	// UninstallCommand is a whole command line. Empty, for an MSI detected by
	// product code, means msiexec /x with that code.
	UninstallCommand string `json:"uninstall_command,omitempty"`
	// SuccessExitCodes are the installer's exit codes that mean it worked.
	SuccessExitCodes []int          `json:"success_exit_codes,omitempty"`
	Detection        *DetectionRule `json:"detection,omitempty"`
	// UninstallPrevious removes the version this one replaces, with that
	// version's own uninstall, before installing: for installers that don't
	// upgrade in place.
	UninstallPrevious bool `json:"uninstall_previous,omitempty"`
}

// IsPackage reports whether this version is an uploaded installer.
func (v AppVersionResponse) IsPackage() bool { return v.Source == AppSourcePackage }

// AppResult is POSTed to /api/agent/v1/apps/{id}/result to report one install
// or uninstall. Only terminal outcomes are reported.
type AppResult struct {
	Version int    `json:"version"`
	Intent  string `json:"intent"`
	Status  string `json:"status"`
	// InstalledVersion is what winget reports afterwards, so the console can
	// say which version a device actually has.
	InstalledVersion string `json:"installed_version"`
	ExitCode         int    `json:"exit_code"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	StdoutTruncated  bool   `json:"stdout_truncated"`
	StderrTruncated  bool   `json:"stderr_truncated"`
	Error            string `json:"error"`
	// Detail is the short sentence the console shows, such as a note that a
	// restart is needed.
	Detail     string    `json:"detail"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}
