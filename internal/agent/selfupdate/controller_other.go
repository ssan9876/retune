//go:build !windows && !darwin && !linux

package selfupdate

// newController fails where there is no service manager self-update knows.
func newController(string) (ServiceController, error) {
	return nil, ErrWindowsOnly
}
