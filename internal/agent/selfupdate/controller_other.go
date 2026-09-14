//go:build !windows

package selfupdate

// newController fails away from Windows: there is no service control
// manager to speak to, so rollback code built for it cannot run here either.
func newController(serviceName string) (ServiceController, error) {
	return nil, ErrWindowsOnly
}
