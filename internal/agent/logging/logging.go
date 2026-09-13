// Package logging builds the agent's logger. A Windows service has no stderr,
// so its output goes to a rotating file, and anything an operator needs to act
// on also goes to the Windows Event Log.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	// maxLogBytes and keptLogs bound the log directory at roughly 25 MB.
	maxLogBytes = 5 << 20
	keptLogs    = 5
)

// Options configures the agent logger.
type Options struct {
	// Dir is the agent data directory; logs land in Dir/logs.
	Dir string
	// Stderr also writes to standard error, for a run from a terminal.
	Stderr bool
	// EventLog forwards warnings and errors to the Windows Event Log.
	EventLog bool
}

// New returns the logger and a function that closes the log file.
func New(opts Options) (*slog.Logger, func() error, error) {
	file, err := NewRotatingFile(filepath.Join(opts.Dir, "logs", "agent.log"), maxLogBytes, keptLogs)
	if err != nil {
		return nil, nil, err
	}
	var w io.Writer = file
	if opts.Stderr {
		w = io.MultiWriter(file, os.Stderr)
	}
	var h slog.Handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	if opts.EventLog {
		h = withEventLog(h)
	}
	return slog.New(h), file.Close, nil
}
