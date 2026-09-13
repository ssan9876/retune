package scripts

import "testing"

// SetUserSession decides, for the duration of one test, whether a signed-in
// user is available. Tests need to cover both answers, and only one of them is
// ever true on the machine running the test.
func SetUserSession(t *testing.T, available bool, reason string) {
	t.Helper()
	previous := userSession
	userSession = func() (bool, string) { return available, reason }
	t.Cleanup(func() { userSession = previous })
}
