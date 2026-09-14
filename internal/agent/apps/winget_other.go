//go:build !windows

package apps

// New returns ErrNoAppInstaller off Windows: winget only exists there, and
// this stub says so rather than pretending.
func New() (Winget, error) { return nil, ErrNoAppInstaller }
