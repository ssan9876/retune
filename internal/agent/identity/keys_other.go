//go:build !windows

package identity

// DefaultKeys returns the platform key provider. Non-Windows builds are
// development-only until the macOS/Linux agents ship.
func DefaultKeys() KeyProvider { return PlainKeys{} }
