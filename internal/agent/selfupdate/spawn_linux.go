//go:build linux

package selfupdate

import (
	"fmt"
	"os/exec"
	"time"
)

// supervisorCommand starts the supervisor as a transient systemd unit of its
// own when systemd is there. A new session is not enough under systemd:
// stopping a service kills every process in its control group, however it
// was started, and the supervisor would die with the agent it is replacing.
// Without systemd-run the agent is not a systemd service either, and a plain
// detached child is all there is.
func supervisorCommand(path, dataDir string) *exec.Cmd {
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		return plainSupervisorCommand(path, dataDir)
	}
	return exec.Command(run, SystemdRunArgs(path, dataDir, time.Now())...)
}

// SystemdRunArgs is how systemd-run is asked to start the supervisor: a
// uniquely named transient service, collected once it exits, without waiting
// for it.
func SystemdRunArgs(path, dataDir string, now time.Time) []string {
	unit := fmt.Sprintf("retune-agent-update-%d", now.Unix())
	return append([]string{"--unit", unit, "--collect", "--quiet", "--no-block", "--", path}, SupervisorArgs(dataDir)...)
}
