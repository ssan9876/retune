//go:build !windows

package selfupdate

import "syscall"

// detachedAttr puts the supervisor in a session, and so a process group, of
// its own. launchd kills whatever is left in a daemon's process group when
// the daemon exits, and the supervisor's first act is to stop that daemon.
func detachedAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
