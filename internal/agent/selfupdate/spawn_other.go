//go:build !windows

package selfupdate

import "syscall"

// detachedAttr has nothing to add away from Windows: self-update is
// Windows-only, so this exists only so the package still builds elsewhere.
func detachedAttr() *syscall.SysProcAttr { return nil }
