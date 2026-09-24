//go:build !windows && !darwin

package inventory

import (
	"context"
	"os"
	"runtime"
	"time"

	"retune/internal/protocol"
)

// NewCollector returns a minimal collector for development on non-Windows
// hosts; real collection arrives with the macOS and Linux agents.
func NewCollector() Collector { return basicCollector{} }

type basicCollector struct{}

func (basicCollector) Collect(context.Context) (protocol.Inventory, error) {
	host, _ := os.Hostname()
	return protocol.Inventory{
		CollectedAt: time.Now().UTC(),
		Hostname:    host,
		OS:          protocol.OSInfo{Name: runtime.GOOS},
	}, nil
}

// HardwareIdentity has no portable implementation yet.
func HardwareIdentity() (string, string) { return "", "" }

// LoggedInUser has no portable implementation yet.
func LoggedInUser() string { return "" }
