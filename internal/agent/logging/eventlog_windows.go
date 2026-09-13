//go:build windows

package logging

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sys/windows/svc/eventlog"
)

// EventLogSource is the Event Log source the installer registers.
const EventLogSource = "Retune"

// eventLogHandler passes every record through to the wrapped handler and also
// sends warnings and errors to the Windows Event Log. Info-level chatter every
// five minutes does not belong in an operator's Event Log.
type eventLogHandler struct {
	slog.Handler
	mu  *sync.Mutex
	log **eventlog.Log
}

// withEventLog wraps h so that warnings and errors also reach the Event Log.
// The source is opened lazily: if it has not been registered, or this process
// is not allowed to write to it, logging to the file must still work.
func withEventLog(h slog.Handler) slog.Handler {
	var el *eventlog.Log
	return &eventLogHandler{Handler: h, mu: new(sync.Mutex), log: &el}
}

func (e *eventLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		e.write(r)
	}
	return e.Handler.Handle(ctx, r)
}

func (e *eventLogHandler) write(r slog.Record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if *e.log == nil {
		el, err := eventlog.Open(EventLogSource)
		if err != nil {
			// Nothing to be done, and the file handler still has the record.
			return
		}
		*e.log = el
	}
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool {
		msg += " " + a.Key + "=" + a.Value.String()
		return true
	})
	if r.Level >= slog.LevelError {
		_ = (*e.log).Error(1, msg)
		return
	}
	_ = (*e.log).Warning(1, msg)
}

func (e *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventLogHandler{Handler: e.Handler.WithAttrs(attrs), mu: e.mu, log: e.log}
}

func (e *eventLogHandler) WithGroup(name string) slog.Handler {
	return &eventLogHandler{Handler: e.Handler.WithGroup(name), mu: e.mu, log: e.log}
}
