//go:build darwin

package selfupdate

import (
	"fmt"
	"os"
)

// The daemon `retune-agent install` and the pkg create.
const (
	launchdLabel = "com.retune.agent"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
)

func newController(string) (ServiceController, error) {
	if _, err := os.Stat(launchdPlist); err != nil {
		return nil, fmt.Errorf("%w: no %s", ErrNotInstalled, launchdPlist)
	}
	return &LaunchdController{Label: launchdLabel, Plist: launchdPlist, Run: execRunner}, nil
}
