//go:build !windows

package policy

import (
	"context"
	"errors"

	"retune/internal/protocol"
)

// The registry, service and local group handlers exist only on Windows. The
// stubs keep the package building elsewhere, and report plainly rather than
// pretending a setting was applied.

var errWindowsOnly = errors.New("this setting kind is only supported on Windows")

// RegistryHandler is a stub away from Windows.
type RegistryHandler struct{}

func (RegistryHandler) Kind() string { return protocol.KindRegistry }
func (RegistryHandler) Get(context.Context, protocol.Setting) (State, error) {
	return State{}, errWindowsOnly
}
func (RegistryHandler) Test(context.Context, protocol.Setting) (bool, error) {
	return false, errWindowsOnly
}
func (RegistryHandler) Set(context.Context, protocol.Setting) error { return errWindowsOnly }

// ServiceHandler is a stub away from Windows.
type ServiceHandler struct{}

func (ServiceHandler) Kind() string { return protocol.KindService }
func (ServiceHandler) Get(context.Context, protocol.Setting) (State, error) {
	return State{}, errWindowsOnly
}
func (ServiceHandler) Test(context.Context, protocol.Setting) (bool, error) {
	return false, errWindowsOnly
}
func (ServiceHandler) Set(context.Context, protocol.Setting) error { return errWindowsOnly }

// GroupHandler is a stub away from Windows.
type GroupHandler struct {
	Run func(ctx context.Context, name string, args ...string) (string, error)
}

func (GroupHandler) Kind() string { return protocol.KindGroup }
func (GroupHandler) Get(context.Context, protocol.Setting) (State, error) {
	return State{}, errWindowsOnly
}
func (GroupHandler) Test(context.Context, protocol.Setting) (bool, error) {
	return false, errWindowsOnly
}
func (GroupHandler) Set(context.Context, protocol.Setting) error { return errWindowsOnly }

// DefaultHandlers are the setting kinds this agent can apply. Away from
// Windows the platform-specific ones report that plainly rather than
// pretending a setting was applied.
func DefaultHandlers(escrow Escrower) []Handler {
	return Handlers(Options{Escrow: escrow})
}
