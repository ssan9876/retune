package selfupdate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultPoll is how often Supervise checks the record for proof of life,
// when the caller does not set one.
const defaultPoll = 2 * time.Second

// restoreTimeout bounds how long restoring the previous build may take when
// it is carried out on a context derived from one that is already done (a
// deadline or a cancellation): the restore must not inherit that doneness, or
// Stop would return immediately and the unproven build would stay wired in.
const restoreTimeout = 30 * time.Second

// stopTimeout bounds the stop that begins an update. A service stuck in
// STOP_PENDING would otherwise hold the supervisor for as long as the service
// control manager is prepared to wait, and the supervisor is the only thing
// standing between this device and a half-applied update.
const stopTimeout = 60 * time.Second

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
	// would leave it pointed at a build that never ran. Leave it alone — but
	// the attempt is still over, and a record left pending is a wedged
	// device: Decide answers "already under way" for ever, with no supervisor
	// left to resolve it. Nothing was touched, so the old build is still
	// wired in and still running; rolled_back is the honest word for that,
	// and the agent that is already there reports it on its next check-in.
	if err := s.stopService(ctx); err != nil {
		s.Log.Error("service would not stop; update abandoned", "err", err)
		rolled := rec
		rolled.Status = StatusRolledBack
		rolled.Detail = fmt.Sprintf("the service would not stop: %v", err)
		if werr := WriteRecord(s.Dir, rolled); werr != nil {
			s.Log.Error("failed to record an update abandoned before it began", "err", werr)
		}
		return fmt.Errorf("stopping service: %w", err)
	}

	// From here on the device is somewhere it cannot be left: stopped, or
	// pointed at a build nothing has proven. Every failure goes through
	// rollback, which puts the previous build back and records the outcome.

	// Step 3: the new binary, the arguments the service already had —
	// losing --data-dir would send the new agent looking for its identity
	// in the wrong place.
	if err := s.Control.SetBinPath(rec.ToBinPath, rec.FromArgs); err != nil {
		s.Log.Error("failed to repoint service at new build", "err", err)
		return s.rollback(ctx, rec, fmt.Sprintf("repointing the service at the new build failed: %v", err))
	}

	// Step 4: so a crash-on-start is retried by the SCM rather than leaving
	// the device dead; a WiX-installed service has none of these.
	if err := s.Control.SetRecoveryActions(); err != nil {
		s.Log.Error("failed to set recovery actions", "err", err)
		return s.rollback(ctx, rec, fmt.Sprintf("setting recovery actions failed: %v", err))
	}

	// Step 5.
	if err := s.Control.Start(); err != nil {
		s.Log.Error("failed to start new build", "err", err)
		return s.rollback(ctx, rec, fmt.Sprintf("starting the new build failed: %v", err))
	}
	s.Log.Info("new build started, waiting for it to check in", "poll", poll)

	// Step 6: proof of life is a check-in, not a start — poll the record,
	// which only the new agent writes, and only once it has actually reached
	// the server.
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		cur, found, err := ReadRecord(s.Dir)
		switch {
		case err != nil:
			// A transient read failure is not proof of anything either way;
			// log it (the log is the only witness this runs with) and keep
			// polling rather than treating it as either success or failure.
			s.Log.Error("failed to read update record while polling", "err", err)
		case found && cur.Status == StatusSucceeded:
			// Step 7: the update stood.
			s.Log.Info("update checked in, keeping it", "to", rec.ToVersion)
			if err := RemoveRecord(s.Dir); err != nil {
				return fmt.Errorf("removing settled update record: %w", err)
			}
			s.pruneOldBuilds(rec)
			return nil
		}

		if !now().Before(rec.Deadline) {
			return s.rollback(ctx, rec, "the new build never checked in before the deadline")
		}

		select {
		case <-ctx.Done():
			// A cancelled supervisor (SIGTERM, machine shutdown) is not the
			// build's fault: recording rolled_back would make Decide refuse
			// this version on this device forever, which is worse than the
			// unproven binary it would be refusing in its place — recovery
			// actions plus the next check-in can still resolve that. So we
			// keep the safety act (restore the previous build) but leave no
			// verdict behind: remove the record so the next run retries
			// cleanly instead of finding either pending or rolled_back.
			s.Log.Warn("supervision cancelled before check-in; restoring previous build without penalizing it", "err", ctx.Err())
			if err := s.restoreBuild(ctx, rec); err != nil {
				s.Log.Error("failed to restore previous build after cancellation", "err", err)
				return fmt.Errorf("restoring previous build after cancellation: %w", err)
			}
			if err := RemoveRecord(s.Dir); err != nil {
				s.Log.Error("failed to remove update record after cancellation", "err", err)
				return fmt.Errorf("removing update record after cancellation: %w", err)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// pruneOldBuilds removes every staged build except the one that just won and
// the one it replaced. The replaced one stays because it is what the service
// is still pointed back at if a later update has to roll back; everything
// else is a binary nobody will ever run again. Nothing here is worth failing
// an update that already succeeded over, so every problem is logged and the
// rest of the sweep carries on.
func (s *Supervisor) pruneOldBuilds(rec Record) {
	binDir := filepath.Join(s.Dir, "bin")
	entries, err := os.ReadDir(binDir)
	if err != nil {
		s.Log.Error("failed to list staged builds", "err", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == rec.ToVersion || e.Name() == rec.FromVersion {
			continue
		}
		path := filepath.Join(binDir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			s.Log.Error("failed to remove an old staged build", "path", path, "err", err)
			continue
		}
		s.Log.Info("removed an old staged build", "version", e.Name())
	}
}

// stillOnNewBuild reports whether the service is, right now, pointed at the
// build an update staged. It is asked only after a restore failed, to decide
// what the record is allowed to claim. A controller that cannot answer leaves
// the rollback verdict standing: there is nothing to contradict it with.
func (s *Supervisor) stillOnNewBuild(rec Record) bool {
	binPath, _, err := s.Control.Config()
	if err != nil {
		s.Log.Error("failed to read the service configuration after a failed restore", "err", err)
		return false
	}
	return strings.EqualFold(filepath.Clean(binPath), filepath.Clean(rec.ToBinPath))
}

// stopService stops the service under stopTimeout, so a service that hangs on
// the way down cannot hold the whole update open indefinitely.
func (s *Supervisor) stopService(ctx context.Context) error {
	sctx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()
	return s.Control.Stop(sctx)
}

// restoreBuild stops the service, repoints it at the previous build with its
// previous arguments, and starts it. It is used both by rollback and by
// cancellation handling, and always runs Stop against a fresh context: the
// context in play when a restore becomes necessary is, by construction,
// already done (deadline exceeded or cancelled), and Stop on a done context
// returns immediately without actually stopping anything.
func (s *Supervisor) restoreBuild(ctx context.Context, rec Record) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
	defer cancel()

	if err := s.Control.Stop(rctx); err != nil {
		return fmt.Errorf("stopping new build: %w", err)
	}
	if err := s.Control.SetBinPath(rec.FromBinPath, rec.FromArgs); err != nil {
		return fmt.Errorf("setting bin path back to previous build: %w", err)
	}
	if err := s.Control.Start(); err != nil {
		return fmt.Errorf("starting previous build: %w", err)
	}
	return nil
}

// rollback puts the previous build back. It is step 8: a rollback is an
// outcome, not an error, so it returns nil once the restore and the record
// both succeed. If the restore itself fails partway — most dangerously, the
// service stopped on the old image but never restarted — the record is still
// written as rolled_back, naming what failed, before returning the error:
// without that, Decide would see a permanently pending record and neither
// report the device nor ever retry it.
func (s *Supervisor) rollback(ctx context.Context, rec Record, detail string) error {
	s.Log.Warn("rolling back update", "detail", detail)

	rolled := rec
	rolled.Status = StatusRolledBack

	if err := s.restoreBuild(ctx, rec); err != nil {
		s.Log.Error("failed to restore previous build during rollback", "err", err)
		rolled.Detail = fmt.Sprintf("%s; restoring the previous build also failed: %v", detail, err)
		// A restore can fail before it repoints anything, which leaves the
		// service wired to the build this rollback was meant to undo. Calling
		// that rolled_back would be a lie the new build then tells the server
		// about itself, if the recovery actions ever bring it up: it would
		// check in and report a rollback while running the very version that
		// supposedly failed. Pending is the honest word for a device nobody
		// has decided about yet -- CheckedIn settles it if the new build does
		// reach the server, and a starting old build expires it.
		if s.stillOnNewBuild(rec) {
			rolled.Status = StatusPending
			rolled.Detail = fmt.Sprintf("%s; restoring the previous build failed: %v; "+
				"the service is still wired to the new build", detail, err)
		}
		if werr := WriteRecord(s.Dir, rolled); werr != nil {
			s.Log.Error("failed to record rollback after a failed restore", "err", werr)
			return fmt.Errorf("restoring previous build: %w (and recording the rollback also failed: %v)", err, werr)
		}
		return fmt.Errorf("restoring previous build: %w", err)
	}

	rolled.Detail = detail
	if err := WriteRecord(s.Dir, rolled); err != nil {
		s.Log.Error("failed to record rollback", "err", err)
		return fmt.Errorf("writing rollback record: %w", err)
	}
	s.Log.Info("rollback complete", "restored", rec.FromVersion)
	return nil
}
