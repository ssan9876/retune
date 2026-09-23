//go:build !windows

package executor

// Off Windows there is nothing to lock, wipe or export: the commands fail
// with a plain reason.
func DefaultLocker() Locker               { return nil }
func DefaultWiper(Runner) Wiper           { return nil }
func DefaultEventExporter() EventExporter { return nil }

// DefaultPasswords is nil off Windows: there are no local accounts to rotate.
func DefaultPasswords() PasswordSetter { return nil }
