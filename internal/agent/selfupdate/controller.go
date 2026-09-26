// Package selfupdate decides whether an agent should replace its own binary
// and records the attempt, so a supervisor process can restore the service
// if the new binary never checks in.
package selfupdate

import (
	"context"
	"errors"
)

// ServiceController is the part of the service control manager an update
// needs. It exists so rollback can be tested without a real service.
type ServiceController interface {
	// Config returns the service's current image path and its arguments.
	//
	// Both are needed, not just the path: a service installed by the MSI has
	// no arguments at all, while one installed manually carries --data-dir.
	// A repoint that dropped the arguments would send the new agent looking
	// for its identity in whatever directory happens to be the default,
	// rather than the one it was actually configured with.
	Config() (binPath string, args []string, err error)

	// SetBinPath repoints the service at a different image, preserving
	// whatever arguments the caller passes.
	SetBinPath(binPath string, args []string) error

	// SetRecoveryActions arranges for the service control manager to restart
	// the service on failure.
	SetRecoveryActions() error

	// Stop asks the service to stop and waits for it to do so, or for ctx to
	// be done.
	Stop(ctx context.Context) error

	// Start starts the service.
	Start() error

	// Running reports whether the service is currently running.
	Running() (bool, error)

	// Close releases the handles to the service and to the service control
	// manager that NewController opened.
	Close() error
}

// ErrWindowsOnly is returned by NewController on a platform with no service
// manager self-update knows how to drive. The name predates macOS and Linux
// support; what it means now is "not Windows, launchd or systemd".
var ErrWindowsOnly = errors.New("self-update needs a Windows service, a launchd daemon or a systemd unit")

// ErrNotInstalled is returned by NewController on macOS and Linux when the
// agent is not installed as a daemon at all -- run by hand, say. There is
// then nothing to repoint, and an update is refused with this reason.
var ErrNotInstalled = errors.New("the agent is not installed as a service, so it cannot update itself")

// ServiceName is both the Windows service name and the Event Log source.
// It is declared here, not in cmd/retune-agent, so the runner and the
// supervise-update subcommand -- which open a controller independently of
// each other -- cannot drift apart on what service they mean.
const ServiceName = "Retune"

// NewController opens the service the agent runs as: the named Windows
// service, the com.retune.agent launchd daemon on macOS, or the
// retune-agent.service systemd unit on Linux. serviceName is the Windows
// service name; the daemon and unit names are fixed by their installers.
func NewController(serviceName string) (ServiceController, error) {
	return newController(serviceName)
}
