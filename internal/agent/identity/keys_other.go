//go:build !windows

package identity

// DefaultKeys returns the platform key provider. Away from Windows the key
// is a plain file; on a Mac it lives in the data directory, which the
// installer makes root's alone.
func DefaultKeys() KeyProvider { return PlainKeys{} }
