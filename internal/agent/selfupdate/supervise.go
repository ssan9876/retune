package selfupdate

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// defaultPoll is how often Supervise checks the record for proof of life,
// when the caller does not set one.
const defaultPoll = 2 * time.Second

// Supervisor carries out an update recorded in Dir and puts the previous
// build back if the new one does not check in. It runs from a copy of the
// outgoing agent, detached, so the code deciding whether the update worked is
// the code that already worked.
type Supervisor struct {
	Dir     string // the data directory, where update.json lives
	Control ServiceController
	Log     *slog.Logger
	Now     func() time.Time
	Poll    time.Duration // how often proof is checked; default 2s
}

// Supervise carries out the update described by the record in Dir, and puts
// the previous build back if the new one does not check in before the
// deadline. It returns nil when the update stuck.
func (s *Supervisor) Supervise(ctx context.Context) error {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	poll := s.Poll
	if poll == 0 {
		poll = defaultPoll
	}

	// Step 1: no pending record means there is nothing for this run to do —
	// the update already settled, or was never started.
	rec, found, err := ReadRecord(s.Dir)
	if err != nil {
		return fmt.Errorf("reading update record: %w", err)
	}
	if !found || rec.Status != StatusPending {
		s.Log.Info("no pending update to supervise")
		return nil
	}

	s.Log.Info("supervising update", "from", rec.FromVersion, "to", rec.ToVersion, "deadline", rec.Deadline)

	// Step 2: if the service will not even stop, touching the image path
	// would leave it pointed at a build that never ran. Leave it alone.
	if err := s.Control.Stop(ctx); err != nil {
		s.Log.Error("service would not stop; update abandoned", "err", err)
		return fmt.Errorf("stopping service: %w", err)
	}

	// Step 3: the new binary, the arguments the service already had —
	// losing --data-dir would send the new agent looking for its identity
	// in the wrong place.
	if err := s.Control.SetBinPath(rec.ToBinPath, rec.FromArgs); err != nil {
		s.Log.Error("failed to repoint service at new build", "err", err)
		return fmt.Errorf("setting bin path to new build: %w", err)
	}

	// Step 4: so a crash-on-start is retried by the SCM rather than leaving
	// the device dead; a WiX-installed service has none of these.
	if err := s.Control.SetRecoveryActions(); err != nil {
		s.Log.Error("failed to set recovery actions", "err", err)
		return fmt.Errorf("setting recovery actions: %w", err)
	}

	// Step 5.
	if err := s.Control.Start(); err != nil {
		s.Log.Error("failed to start new build", "err", err)
		return fmt.Errorf("starting new build: %w", err)
	}
	s.Log.Info("new build started, waiting for it to check in", "poll", poll)

	// Step 6: proof of life is a check-in, not a start — poll the record,
	// which only the new agent writes, and only once it has actually reached
	// the server.
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		cur, found, err := ReadRecord(s.Dir)
		if err == nil && found && cur.Status == StatusSucceeded {
			// Step 7: the update stood.
			s.Log.Info("update checked in, keeping it", "to", rec.ToVersion)
			if err := RemoveRecord(s.Dir); err != nil {
				return fmt.Errorf("removing settled update record: %w", err)
			}
			return nil
		}

		if !now().Before(rec.Deadline) {
			return s.rollback(ctx, rec, "the new build never checked in before the deadline")
		}

		select {
		case <-ctx.Done():
			return s.rollback(ctx, rec, "supervision was cancelled before the new build checked in")
		case <-ticker.C:
		}
	}
}

// rollback puts the previous build back. It is step 8: a rollback is an
// outcome, not an error, so it always returns nil unless recording it fails.
func (s *Supervisor) rollback(ctx context.Context, rec Record, detail string) error {
	s.Log.Warn("rolling back update", "detail", detail)

	if err := s.Control.Stop(ctx); err != nil {
		s.Log.Error("failed to stop failed new build during rollback", "err", err)
		return fmt.Errorf("stopping failed new build: %w", err)
	}
	if err := s.Control.SetBinPath(rec.FromBinPath, rec.FromArgs); err != nil {
		s.Log.Error("failed to repoint service back at previous build", "err", err)
		return fmt.Errorf("setting bin path back to previous build: %w", err)
	}
	if err := s.Control.Start(); err != nil {
		s.Log.Error("failed to start previous build during rollback", "err", err)
		return fmt.Errorf("starting previous build: %w", err)
	}

	rolled := rec
	rolled.Status = StatusRolledBack
	rolled.Detail = detail
	if err := WriteRecord(s.Dir, rolled); err != nil {
		s.Log.Error("failed to record rollback", "err", err)
		return fmt.Errorf("writing rollback record: %w", err)
	}
	s.Log.Info("rollback complete", "restored", rec.FromVersion)
	return nil
}
