//go:build !windows && !darwin

package executor

import (
	"context"
	"errors"
	"io"
	"time"
)

// errUnsupported is returned by the development stubs on non-Windows hosts.
var errUnsupported = errors.New("command execution is only implemented on Windows")

// DefaultRunner returns a stub until the macOS and Linux agents ship.
func DefaultRunner(string) Runner { return unsupported{} }

// DefaultRestarter returns a stub until the macOS and Linux agents ship.
func DefaultRestarter() Restarter { return unsupported{} }

type unsupported struct{}

func (unsupported) RunPowerShell(context.Context, string, io.Writer, io.Writer) (int, error) {
	return -1, errUnsupported
}

func (unsupported) Restart(time.Duration, string) error { return errUnsupported }
