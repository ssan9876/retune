package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"retune/internal/agent/client"
	"retune/internal/protocol"
)

// binName is the executable staged under each version's directory. It is
// what the supervisor repoints the service at, and what a restored service
// runs again after a rollback.
const binName = "retune-agent.exe"

// supervisorName is the copy of the running agent that carries out the
// update. It has to be a copy: the service's own image is locked and is
// about to be stopped, so nothing can run straight out of it.
const supervisorName = "supervisor.exe"

// Client is the part of the agent's server connection the syncer needs.
type Client interface {
	FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error)
	DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error
	ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error
}

// Syncer downloads, verifies and stages an assigned agent build, and hands
// off to the supervisor that carries the update the rest of the way.
type Syncer struct {
	Dir      string // the data directory
	Client   Client
	Control  ServiceController // reads the live service's path and arguments
	Running  string            // this build's version
	Injected bool
	Log      *slog.Logger
	Now      func() time.Time

	// Rollback, when set, is a previous attempt that was rolled back and has
	// not been reported yet. The restored agent reports it on its next
	// check-in and then clears the record: the supervisor cannot, because by
	// the time it decides, the agent it was testing is gone.
	Rollback *Record

	// Spawn starts the supervisor. It is a field so a test can observe the
	// hand-off without launching a process.
	Spawn func(supervisorPath string) error

	// mu serialises whole Sync cycles against each other: the session starts
	// one per check-in without waiting for the last, and two of them staging
	// the same build would hand off twice.
	mu sync.Mutex

	// recordMu guards update.json alone, and deliberately is not mu. Sync
	// holds mu across a download that can run for as long as the download
	// timeout, while CheckedIn runs inline on the check-in path: one lock for
	// both would mean a device in the middle of an update stops checking in
	// altogether, which is precisely what dispatching syncers in the
	// background exists to prevent.
	recordMu sync.Mutex
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// readRecord, writeRecord and removeRecord are every touch this type makes on
// update.json, all of them under recordMu. Anything that has to read and then
// write one state -- CheckedIn, markReported -- takes recordMu itself and holds
// it across both, so no other goroutine can slip a different record in between.
func (s *Syncer) readRecord() (Record, bool, error) {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	return ReadRecord(s.Dir)
}

func (s *Syncer) writeRecord(rec Record) error {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	return WriteRecord(s.Dir, rec)
}

func (s *Syncer) removeRecord() error {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	return RemoveRecord(s.Dir)
}

// Sync processes the items from one check-in, staging whatever agent build
// is due. Items of other kinds are ignored, which is how an older agent
// copes with a newer server.
func (s *Syncer) Sync(ctx context.Context, items []protocol.Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A rollback can also arrive without a restart behind it: a supervisor that
	// could not stop the service writes one while this very process keeps
	// running, so nothing handed it a Rollback at startup. Adopting whatever
	// unreported rollback is on disk is what keeps that outcome from waiting
	// for the next service restart to reach the console.
	if s.Rollback == nil {
		if rec, found, err := s.readRecord(); err != nil {
			s.log().Error("failed to read the update record", "error", err)
		} else if found && rec.Status == StatusRolledBack && !rec.Reported {
			s.log().Warn("adopting a rollback this process was not restarted for",
				"attempted", rec.ToVersion, "restored", rec.FromVersion, "detail", rec.Detail)
			s.Rollback = &rec
		}
	}

	// A pending rollback is reported before anything else: it describes an
	// attempt that has already been resolved, and nothing else will ever
	// report it, since the agent that decided to roll back is gone.
	if s.Rollback != nil {
		rec := *s.Rollback
		err := s.report(ctx, rec.ItemID, rec.FromVersion, protocol.ResultFailed, rec.ToVersion, rec.Detail)
		switch {
		case err == nil:
			s.markReported(rec)
			s.Rollback = nil
		case isGone(err):
			// Ruling: a 404 here means the build was deleted or unassigned
			// server-side, so nothing will ever accept this report. Retrying
			// it on every check-in forever is worse than giving up on it, so
			// this is treated as resolved rather than transient.
			s.log().Warn("rollback report was rejected as gone; giving up on it", "error", err)
			s.markReported(rec)
			s.Rollback = nil
		default:
			// Left set, so the next cycle tries again instead of losing the
			// only record of what happened.
			s.log().Error("failed to report rollback", "error", err)
		}
	}

	for _, item := range items {
		if item.Kind != protocol.ItemKindAgent {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.syncOne(ctx, item); err != nil {
			// One bad build must not stop the rest, and the next check-in is
			// the retry for anything transient.
			s.log().Warn("agent update failed", "item_id", item.ID, "error", err)
		}
	}
	return nil
}

// markReported records that a rollback has been told to the server. The
// record stays: it is what stops Decide from installing the same failed
// version again, possibly within this very check-in, and only a stage of a
// different version clears it.
//
// The record is re-read rather than rewritten from the copy being reported. A
// report can fail for several check-ins before it gets through, and a different
// build can be assigned and staged in the meantime; writing the old rollback
// back over that pending attempt would destroy the only thing its supervisor
// and any rollback of it have to go on.
func (s *Syncer) markReported(rec Record) {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()

	cur, found, err := ReadRecord(s.Dir)
	if err != nil {
		s.log().Error("failed to re-read the update record before marking it reported", "error", err)
		return
	}
	if !found || cur.ToVersion != rec.ToVersion || cur.Status != rec.Status {
		s.log().Info("the update record has moved on since this rollback; leaving it alone",
			"reported", rec.ToVersion)
		return
	}
	cur.Reported = true
	if err := WriteRecord(s.Dir, cur); err != nil {
		s.log().Error("failed to record that a rollback was reported", "error", err)
	}
}

// CheckedIn is called by the session after every check-in that reached the
// server. It is the proof of life the supervisor waits for: if this build is
// the one a pending record was staged for, the record is marked succeeded.
//
// It is deliberately not gated on Injected. A build that got this far is by
// definition the one that was staged, and if it somehow was not stamped,
// Running is the placeholder and will not match the record's ToVersion.
//
// It takes recordMu and not mu: the session calls this on the check-in path, and
// waiting on a Sync that is halfway through a download would stop the device
// checking in at all.
func (s *Syncer) CheckedIn() error {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()

	rec, found, err := ReadRecord(s.Dir)
	if err != nil {
		return fmt.Errorf("read record: %w", err)
	}
	if !found || rec.Status != StatusPending || rec.ToVersion != s.Running {
		return nil
	}
	rec.Status = StatusSucceeded
	if err := WriteRecord(s.Dir, rec); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	s.log().Info("this build checked in; the update stands", "from", rec.FromVersion, "to", rec.ToVersion)
	return nil
}

func (s *Syncer) syncOne(ctx context.Context, item protocol.Item) error {
	opts, err := protocol.ParseAgentOptions(item.Options)
	if err != nil {
		return fmt.Errorf("options: %w", err)
	}
	rec, _, err := s.readRecord()
	if err != nil {
		return fmt.Errorf("read record: %w", err)
	}
	def, err := s.Client.FetchAgentVersion(ctx, item.ID)
	if err != nil {
		return fmt.Errorf("fetch agent version: %w", err)
	}

	decision := Decide(s.Running, def.Version, s.Injected, rec)
	if decision.Action == ActionNone {
		if !s.Injected {
			// The only refusal reason worth telling anyone about: a
			// build with no injected version updates on every check-in on
			// every machine unless it is told, loudly, why it will not.
			if err := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", decision.Reason); err != nil {
				return fmt.Errorf("report refusal: %w", err)
			}
			return nil
		}
		s.log().Debug("agent update not due", "item_id", item.ID, "reason", decision.Reason)
		return nil
	}

	return s.stage(ctx, item, opts, def)
}

// stage downloads, verifies and stages the assigned build, records the
// attempt, and hands off to the supervisor. Every terminal failure along the
// way is reported: an update merely under way is not, since the supervisor
// owns that report.
func (s *Syncer) stage(ctx context.Context, item protocol.Item, opts protocol.AgentOptions, def protocol.AgentVersionResponse) error {
	if s.Control == nil {
		// Refuse before touching anything. A record written with an empty
		// FromBinPath/FromArgs would strip --data-dir from a hand-installed
		// service on repoint -- it would boot against the wrong data
		// directory and never check in -- and a rollback would then feed an
		// empty path into SetBinPath, bricking the service one way or the
		// other. Pretending to act here is worse than refusing.
		if repErr := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", ErrWindowsOnly.Error()); repErr != nil {
			return fmt.Errorf("report refusal: %w", repErr)
		}
		return nil
	}

	versionDir := filepath.Join(s.Dir, "bin", def.Version)
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		return fmt.Errorf("create version dir: %w", err)
	}
	binPath := filepath.Join(versionDir, binName)
	partPath := binPath + ".part"

	if err := s.download(ctx, item.ID, def.SHA256, partPath); err != nil {
		// DownloadAgentBinary hashes as it streams, so a mismatch is only
		// discovered after wrong bytes are already on disk. A wrong binary
		// left behind is worse than no binary, so the whole version
		// directory goes, not just the .part file.
		if rmErr := os.RemoveAll(versionDir); rmErr != nil {
			s.log().Error("failed to remove partial download", "error", rmErr)
		}
		if repErr := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", err.Error()); repErr != nil {
			s.log().Error("failed to report download failure", "error", repErr)
		}
		return fmt.Errorf("download: %w", err)
	}

	if err := os.Rename(partPath, binPath); err != nil {
		if rmErr := os.RemoveAll(versionDir); rmErr != nil {
			s.log().Error("failed to remove partial download", "error", rmErr)
		}
		if repErr := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", err.Error()); repErr != nil {
			s.log().Error("failed to report stage failure", "error", repErr)
		}
		return fmt.Errorf("stage binary: %w", err)
	}

	// Only the live service knows whether this device was installed by the
	// MSI (no arguments) or by hand (--data-dir); nothing else can tell.
	fromBinPath, fromArgs, err := s.Control.Config()
	if err != nil {
		if rmErr := os.RemoveAll(versionDir); rmErr != nil {
			s.log().Error("failed to remove staged build", "error", rmErr)
		}
		if repErr := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", err.Error()); repErr != nil {
			s.log().Error("failed to report controller failure", "error", repErr)
		}
		return fmt.Errorf("read service config: %w", err)
	}

	now := s.now()
	rec := Record{
		ItemID:      item.ID,
		FromVersion: s.Running,
		FromBinPath: fromBinPath,
		FromArgs:    fromArgs,
		ToVersion:   def.Version,
		ToBinPath:   binPath,
		StartedAt:   now,
		Deadline:    now.Add(opts.Deadline()),
		Status:      StatusPending,
	}
	if err := s.writeRecord(rec); err != nil {
		if rmErr := os.RemoveAll(versionDir); rmErr != nil {
			s.log().Error("failed to remove staged build", "error", rmErr)
		}
		if repErr := s.report(ctx, item.ID, def.Version, protocol.ResultFailed, "", err.Error()); repErr != nil {
			s.log().Error("failed to report record failure", "error", repErr)
		}
		return fmt.Errorf("write record: %w", err)
	}

	// A copy, because the service image is locked and about to be stopped.
	supervisorPath := filepath.Join(s.Dir, supervisorName)
	if err := copyRunningExecutable(supervisorPath); err != nil {
		return s.abandon(ctx, item.ID, def.Version, versionDir, fmt.Sprintf("copying the supervisor: %v", err), err)
	}
	if s.Spawn == nil {
		// Treated exactly like a Spawn error, not a panic, and this all
		// happens with s.mu held: a nil Spawn must fail the update, not the
		// whole syncer.
		return s.abandon(ctx, item.ID, def.Version, versionDir, "no Spawn function was configured", nil)
	}
	if err := s.Spawn(supervisorPath); err != nil {
		return s.abandon(ctx, item.ID, def.Version, versionDir, fmt.Sprintf("spawning the supervisor: %v", err), err)
	}
	return nil
}

// abandon undoes a staged update that failed at hand-off. Without this, a
// broken copy or Spawn would leave the record pending forever: Decide would
// answer "already under way" on every future check-in, with no supervisor
// left to ever resolve it -- a silently dead device.
//
// detail is what the server is told, in the words an administrator reads;
// cause, where there is one, is what the returned error wraps, so a caller
// can still reach the original failure rather than a string that only looks
// like it.
func (s *Syncer) abandon(ctx context.Context, id, version, versionDir, detail string, cause error) error {
	if err := s.removeRecord(); err != nil {
		s.log().Error("failed to remove abandoned update record", "error", err)
	}
	if err := os.RemoveAll(versionDir); err != nil {
		s.log().Error("failed to remove abandoned staged build", "error", err)
	}
	if err := s.report(ctx, id, version, protocol.ResultFailed, "", detail); err != nil {
		s.log().Error("failed to report abandoned update", "error", err)
	}
	if cause != nil {
		return fmt.Errorf("%s: %w", detail, cause)
	}
	return errors.New(detail)
}

// isGone reports whether err is the server telling us, definitively, that
// there is nothing to report against any more -- a build that was deleted or
// unassigned. Any other error is treated as transient.
func isGone(err error) bool {
	var he *client.HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

func (s *Syncer) download(ctx context.Context, id, wantSHA256, partPath string) error {
	f, err := os.Create(partPath)
	if err != nil {
		return fmt.Errorf("create part file: %w", err)
	}
	defer f.Close()
	return s.Client.DownloadAgentBinary(ctx, id, wantSHA256, f)
}

// report sends one terminal outcome to the server.
func (s *Syncer) report(ctx context.Context, id, version, status, rolledBackFrom, detail string) error {
	r := protocol.AgentUpdateResult{
		Version:        version,
		Status:         status,
		RolledBackFrom: rolledBackFrom,
		Detail:         detail,
		ReportedAt:     s.now(),
	}
	return s.Client.ReportAgentUpdate(ctx, id, r)
}

// copyRunningExecutable copies this process's own binary to dst, through a
// temp file and rename so a reader never sees a half-written supervisor.
func copyRunningExecutable(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	src, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("open running executable: %w", err)
	}
	defer src.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create supervisor copy: %w", err)
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("copy running executable: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close supervisor copy: %w", err)
	}
	return os.Rename(tmp, dst)
}
