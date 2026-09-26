//go:build !windows && !linux

package selfupdate

import "os/exec"

// supervisorCommand runs the supervisor directly; detachedAttr gives it a
// session of its own, which is what survives launchd stopping the daemon.
func supervisorCommand(path, dataDir string) *exec.Cmd { return plainSupervisorCommand(path, dataDir) }
