//go:build !windows

package logging

import "log/slog"

// withEventLog is a no-op away from Windows.
func withEventLog(h slog.Handler) slog.Handler { return h }
