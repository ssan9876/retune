//go:build windows

package selfupdate

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachedAttr detaches the supervisor from the parent's console and job so
// it keeps running after the service that spawned it stops: without
// DETACHED_PROCESS, the supervisor inherits a console that is about to go
// away with its parent, and CREATE_NO_WINDOW keeps it from flashing one open.
func detachedAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NO_WINDOW}
}
