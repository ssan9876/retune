package selfupdate

import "os/exec"

// SpawnSupervisor starts a detached copy of the outgoing build. It must
// outlive the service that starts it -- that service is about to be stopped
// by the very process being spawned.
func SpawnSupervisor(path string) error {
	cmd := exec.Command(path, "supervise-update")
	cmd.SysProcAttr = detachedAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
