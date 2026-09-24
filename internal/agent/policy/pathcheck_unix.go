//go:build !windows

package policy

import (
	"io/fs"
	"path/filepath"
	"syscall"
)

// trustedSystemLink allows a root-owned link directly under the root folder,
// such as macOS's /var, /tmp and /etc, which lead to /private: only root can
// put a link there, so it cannot be one somebody planted.
func trustedSystemLink(path string, info fs.FileInfo) bool {
	if filepath.Dir(path) != "/" || info.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
