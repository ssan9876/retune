//go:build linux

package selfupdate

import (
	"context"
	"fmt"
	"strings"
)

// The unit deploy/linux/retune-agent.service installs.
const (
	systemdUnit   = "retune-agent.service"
	systemdDropIn = "/etc/systemd/system/" + systemdUnit + ".d"
)

func newController(string) (ServiceController, error) {
	c := &SystemdController{Unit: systemdUnit, DropInDir: systemdDropIn, Run: execRunner}
	// LoadState is "loaded" only for a unit systemd has a file for; "not-found"
	// is an agent run by hand, and an error is a machine without systemd.
	out, err := c.Run(context.Background(), "systemctl", "show", "--property=LoadState", "--value", systemdUnit)
	if err != nil || strings.TrimSpace(string(out)) != "loaded" {
		return nil, fmt.Errorf("%w: no %s unit", ErrNotInstalled, systemdUnit)
	}
	return c, nil
}
