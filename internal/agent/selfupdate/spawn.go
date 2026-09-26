package selfupdate

import "os/exec"

// SpawnSupervisor starts a detached copy of the outgoing build. It must
// outlive the service that starts it -- that service is about to be stopped
// by the very process being spawned. dataDir travels with it, so an agent
// installed with --data-dir is supervised out of the directory it actually
// uses rather than the platform default.
func SpawnSupervisor(path, dataDir string) error {
	cmd := supervisorCommand(path, dataDir)
	cmd.SysProcAttr = detachedAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// SupervisorArgs is the supervise-update command line, shared by every
// platform's way of starting it.
func SupervisorArgs(dataDir string) []string {
	return []string{"supervise-update", "--data-dir", dataDir}
}

// plainSupervisorCommand runs the supervisor directly, as a child process.
func plainSupervisorCommand(path, dataDir string) *exec.Cmd {
	return exec.Command(path, SupervisorArgs(dataDir)...)
}
