// Package serverupdate updates a running Retune server to a newer signed
// release: in a Docker Compose deployment through the retune-updater service,
// and in a plain binary install through `retune-server update-apply` under
// systemd.
//
// Whatever applies an update trusts nothing the server tells it except which
// version to go to. It fetches release.json and its signature itself, verifies
// them against the release keys, and takes the image digest or binary hash it
// installs from that manifest alone - so a compromised server can ask for an
// update, but cannot choose what gets installed.
//
// An update is: verify, back up the database, fetch the new build, swap it in,
// and wait for the new server to report ready. If it does not, the previous
// build is put back. Migrations run when the new server starts, so a rollback
// after one relies on the backup taken first; the console says so before an
// administrator confirms.
package serverupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"retune/internal/release"
	"retune/internal/version"
)

// The phases an update passes through, in order, and how it ends.
const (
	PhaseQueued     = "queued"
	PhaseVerifying  = "verifying"
	PhaseBackingUp  = "backing_up"
	PhasePulling    = "pulling"
	PhaseRestarting = "restarting"
	// PhaseHealthy is an update that finished: the new server is ready.
	PhaseHealthy = "healthy"
	// PhaseRolledBack is an update that failed after the swap and was undone:
	// the previous build is running again.
	PhaseRolledBack = "rolled_back"
	// PhaseFailed is an update that stopped before changing anything, or whose
	// rollback also failed. Error says which.
	PhaseFailed = "failed"
)

// Request asks for one update.
type Request struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

// State is how an update is going, or how it went.
type State struct {
	ID          string     `json:"id"`
	Version     string     `json:"version"`
	FromVersion string     `json:"from_version,omitempty"`
	Phase       string     `json:"phase"`
	Detail      string     `json:"detail,omitempty"`
	Error       string     `json:"error,omitempty"`
	Backup      string     `json:"backup,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// Done reports whether the update has finished, one way or the other.
func (s State) Done() bool {
	return s.Phase == PhaseHealthy || s.Phase == PhaseRolledBack || s.Phase == PhaseFailed
}

// Env is where an update is carried out: a Compose project or a binary under
// systemd.
type Env interface {
	// Current is the version running now.
	Current(ctx context.Context) (string, error)
	// Backup dumps the database and returns where the dump is.
	Backup(ctx context.Context, name string) (string, error)
	// Stage fetches the new build the manifest names and checks it, returning
	// what Swap installs.
	Stage(ctx context.Context, m release.ReleaseManifest) (string, error)
	// Swap installs target and restarts the server on it, returning what
	// Restore needs to put the previous build back. A failed Swap still
	// returns previous when it got far enough to need undoing.
	Swap(ctx context.Context, target string) (previous string, err error)
	// WaitHealthy waits for the server to report ready.
	WaitHealthy(ctx context.Context) error
	// Restore puts the previous build back and restarts the server on it.
	Restore(ctx context.Context, previous string) error
}

// Fetcher gets a release's manifest and signature, exactly as published.
type Fetcher interface {
	Fetch(ctx context.Context, version string) (manifest, signature []byte, err error)
}

// Errors an update can be refused with before it starts.
var (
	ErrNotNewer = errors.New("that version is not newer than the one running")
	ErrBusy     = errors.New("an update is already in progress")
)

// Verify checks a release manifest and its signature against the release
// keys, and that it is the version asked for and newer than current. Only a
// verified manifest is returned.
func Verify(keys []release.PublicKey, raw, sigRaw []byte, want, current string) (release.ReleaseManifest, error) {
	sig, err := release.DecodeSidecar(sigRaw)
	if err != nil {
		return release.ReleaseManifest{}, fmt.Errorf("release.json.sig: %w", err)
	}
	m, err := release.VerifyReleaseManifest(keys, raw, sig)
	if err != nil {
		return release.ReleaseManifest{}, fmt.Errorf("release %s did not verify: %w", want, err)
	}
	if m.Version != strings.TrimPrefix(want, "v") {
		return release.ReleaseManifest{}, fmt.Errorf("asked for %s, but the manifest is for %s", want, m.Version)
	}
	if !Newer(m.Version, current) {
		return release.ReleaseManifest{}, fmt.Errorf("%w: %s is running and %s was asked for", ErrNotNewer, current, m.Version)
	}
	return m, nil
}

// Newer reports whether candidate is newer than current. An empty or
// unparsable current version is treated as a development build, which every
// release is newer than.
func Newer(candidate, current string) bool {
	if _, err := release.ParseVersion(current); err != nil {
		current = version.DevVersion
	}
	return release.Newer(candidate, current)
}

// Updater runs updates in one Env.
type Updater struct {
	Env   Env
	Fetch Fetcher
	// Keys are the release keys a manifest must be signed by.
	Keys []release.PublicKey
	// Save records each change of state where the console can read it.
	Save func(State) error
	Now  func() time.Time
	Log  *slog.Logger
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run carries out one update and returns how it ended. It never panics out
// and never returns early: every path ends in a finished state, saved.
func (u *Updater) Run(ctx context.Context, req Request) State {
	st := State{
		ID: req.ID, Version: req.Version, RequestedBy: req.RequestedBy,
		Phase: PhaseQueued, StartedAt: u.now(),
	}
	set := func(phase, detail string) {
		st.Phase, st.Detail, st.UpdatedAt = phase, detail, u.now()
		if st.Done() {
			t := st.UpdatedAt
			st.FinishedAt = &t
		}
		if u.Save != nil {
			if err := u.Save(st); err != nil {
				u.log().Warn("save the update state", "error", err)
			}
		}
		u.log().Info("server update", "version", st.Version, "phase", phase, "detail", detail)
	}
	fail := func(err error) State {
		st.Error = err.Error()
		set(PhaseFailed, "")
		return st
	}
	set(PhaseQueued, "")

	set(PhaseVerifying, "checking the signed release manifest")
	current, err := u.Env.Current(ctx)
	if err != nil {
		return fail(fmt.Errorf("read the running version: %w", err))
	}
	st.FromVersion = current
	raw, sigRaw, err := u.Fetch.Fetch(ctx, req.Version)
	if err != nil {
		return fail(fmt.Errorf("fetch release %s: %w", req.Version, err))
	}
	m, err := Verify(u.Keys, raw, sigRaw, req.Version, current)
	if err != nil {
		return fail(err)
	}

	set(PhaseBackingUp, "dumping the database")
	name := fmt.Sprintf("retune-%s-to-%s-%s", safe(current), safe(m.Version), u.now().UTC().Format("20060102T150405Z"))
	if st.Backup, err = u.Env.Backup(ctx, name); err != nil {
		return fail(fmt.Errorf("back up the database: %w", err))
	}

	set(PhasePulling, "fetching the new build")
	target, err := u.Env.Stage(ctx, m)
	if err != nil {
		return fail(fmt.Errorf("fetch the new build: %w", err))
	}

	set(PhaseRestarting, "starting the server on "+m.Version)
	previous, swapErr := u.Env.Swap(ctx, target)
	healthErr := swapErr
	if swapErr == nil {
		healthErr = u.Env.WaitHealthy(ctx)
	}
	if healthErr == nil {
		set(PhaseHealthy, "running "+m.Version)
		return st
	}

	// The new build did not come up: put the old one back.
	st.Error = healthErr.Error()
	if previous == "" {
		set(PhaseFailed, "the server could not be restarted, and there was nothing to roll back to")
		return st
	}
	set(PhaseRestarting, "rolling back to "+current)
	if err := u.Env.Restore(ctx, previous); err != nil {
		st.Error = fmt.Sprintf("%s; rolling back also failed: %v", st.Error, err)
		set(PhaseFailed, "")
		return st
	}
	if err := u.Env.WaitHealthy(ctx); err != nil {
		st.Error = fmt.Sprintf("%s; after rolling back the server is still not ready: %v", st.Error, err)
		set(PhaseFailed, "")
		return st
	}
	set(PhaseRolledBack, "running "+current+" again")
	return st
}

// safe keeps a version usable in a file name.
func safe(s string) string {
	if s == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, s)
}
