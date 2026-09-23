package apps

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// Client is the part of the agent's server connection the syncer needs.
type Client interface {
	FetchApp(ctx context.Context, id string, version int) (protocol.AppVersionResponse, error)
	ReportAppResult(ctx context.Context, id string, r protocol.AppResult) error
}

// Syncer installs and removes the apps assigned to this device.
type Syncer struct {
	State  *state.Store
	Client Client
	Winget Winget
	Log    *slog.Logger
	Now    func() time.Time

	// Unavailable, when set, is why Winget could not be constructed on this
	// machine at all (see apps.New): no App Installer, or not Windows. Every
	// assigned winget app is then reported failed with this reason instead of
	// being acted on — Winget is never touched, since there is no working one
	// to call.
	Unavailable error

	// Packages installs uploaded MSI and EXE packages, and
	// PackagesUnavailable is why it can't on this machine, as Unavailable is
	// for winget. The two are independent: a machine with no App Installer
	// can still run an MSI.
	Packages            Installer
	PackagesUnavailable error

	// mu keeps one winget invocation running at a time: two of them fighting
	// over the same package source is rarely what an administrator meant.
	mu sync.Mutex
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

// Sync processes the items from one check-in, installing or removing whatever
// is due. Items of other kinds are ignored, which is how an older agent
// copes with a newer server.
func (s *Syncer) Sync(ctx context.Context, items []protocol.Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range items {
		if item.Kind != protocol.ItemKindApp {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.syncOne(ctx, item); err != nil {
			// One bad deployment must not stop the rest.
			s.log().Warn("app deployment failed", "app_id", item.ID, "error", err)
		}
	}
	return nil
}

// installerFor picks what acts on v, or says why nothing on this machine can.
func (s *Syncer) installerFor(v protocol.AppVersionResponse) (Installer, error) {
	if v.IsPackage() {
		switch {
		case s.PackagesUnavailable != nil:
			return nil, s.PackagesUnavailable
		case s.Packages == nil:
			return nil, errors.New("this agent can't install uploaded packages")
		}
		return s.Packages, nil
	}
	switch {
	case s.Unavailable != nil:
		return nil, s.Unavailable
	case s.Winget == nil:
		return nil, ErrNoAppInstaller
	}
	return wingetInstaller{s.Winget}, nil
}

// reportUnavailable reports one assigned app as failed because this machine
// cannot install its kind of app at all, instead of trying to act on it. It
// reports once per app per version — the same way a real result is
// remembered — so an hourly check-in on a machine that will never gain an App
// Installer does not fill the install history with an identical failure
// forever.
func (s *Syncer) reportUnavailable(ctx context.Context, item protocol.Item, opts protocol.AppOptions,
	st state.AppState, why error) error {
	if st.Version == item.Version && st.LastStatus == protocol.ResultFailed {
		return nil
	}

	now := s.now()
	next := st
	next.Version, next.Intent = item.Version, opts.Intent
	next.LastActedAt = now
	next.LastStatus = protocol.ResultFailed
	next.Settled = false
	if err := s.State.SetAppState(item.ID, next); err != nil {
		return fmt.Errorf("record local state: %w", err)
	}

	result := protocol.AppResult{
		Version: item.Version, Intent: opts.Intent,
		Status: protocol.ResultFailed, Detail: why.Error(),
		StartedAt: now, FinishedAt: now,
	}
	if err := s.Client.ReportAppResult(ctx, item.ID, result); err != nil {
		return fmt.Errorf("report result: %w", err)
	}
	return nil
}

func (s *Syncer) syncOne(ctx context.Context, item protocol.Item) error {
	opts, err := protocol.ParseAppOptions(item.Options)
	if err != nil {
		return fmt.Errorf("options: %w", err)
	}
	st, err := s.State.AppState(item.ID)
	if err != nil {
		return fmt.Errorf("read local state: %w", err)
	}

	decision := Decide(item.Version, opts, st, s.now())
	return s.apply(ctx, item, opts, st, decision, true)
}

// apply carries out one decision. allowDetect is false on the re-decide that
// follows a detection, so a bug in Decide that asked to detect twice in one
// cycle cannot turn into an infinite loop here.
func (s *Syncer) apply(ctx context.Context, item protocol.Item, opts protocol.AppOptions,
	st state.AppState, decision Decision, allowDetect bool) error {

	switch decision.Action {
	case ActionNone:
		s.log().Debug("app not due", "app_id", item.ID, "reason", decision.Reason)
		return nil
	case ActionDetect:
		if !allowDetect {
			return nil
		}
		return s.detect(ctx, item, opts, st)
	case ActionInstall:
		return s.install(ctx, item, opts, st)
	case ActionUninstall:
		return s.uninstall(ctx, item, opts, st)
	default:
		return nil
	}
}

// detect refreshes what is remembered about one app and then re-decides once,
// so a detection that finds the app missing (or present when it should be
// gone) is acted on in the same cycle. If detection instead confirms the app
// is already in its desired state — install finding it present, or uninstall
// finding it absent — that is reported too, but only on the transition into
// that settled state: once st.Settled already says this version/intent was
// confirmed before, a repeat detection (the hourly recheck) reports nothing,
// since there is no news.
func (s *Syncer) detect(ctx context.Context, item protocol.Item, opts protocol.AppOptions, st state.AppState) error {
	v, err := s.Client.FetchApp(ctx, item.ID, item.Version)
	if err != nil {
		return fmt.Errorf("fetch app: %w", err)
	}

	inst, why := s.installerFor(v)
	if why != nil {
		return s.reportUnavailable(ctx, item, opts, st, why)
	}
	installed, _, r := inst.Detect(ctx, item.ID, v)
	if r.Err != nil {
		// A failed detection is not an answer, only a failed attempt to get
		// one: treating it as "not installed" would make the agent reinstall
		// (or remove) software on every cycle for as long as winget or the
		// package source is unreachable. Leave the remembered state alone.
		s.log().Warn("detecting app failed", "app_id", item.ID, "package_id", v.PackageID,
			"file_name", v.FileName, "error", r.Err)
		return nil
	}

	// A new version or changed intent is a fresh instruction; the old
	// failures (and any earlier settled report) belonged to whatever was
	// assigned before, not to this one.
	fresh := st.Version != item.Version || st.Intent != opts.Intent
	next := st
	next.Version, next.Intent = item.Version, opts.Intent
	next.Installed = installed
	next.LastSeenAt = s.now()
	if fresh {
		next.Failures = 0
		next.Settled = false
	}

	want := opts.Intent == protocol.IntentInstall
	settledNow := installed == want
	reportSettle := settledNow && !next.Settled
	next.Settled = settledNow

	if err := s.State.SetAppState(item.ID, next); err != nil {
		return fmt.Errorf("record local state: %w", err)
	}

	if reportSettle {
		detail := "already installed"
		if !want {
			detail = "already absent"
		}
		now := s.now()
		result := protocol.AppResult{
			Version: item.Version, Intent: opts.Intent,
			Status: protocol.ResultSucceeded, Detail: detail,
			StartedAt: now, FinishedAt: now,
		}
		if err := s.Client.ReportAppResult(ctx, item.ID, result); err != nil {
			return fmt.Errorf("report result: %w", err)
		}
		return nil
	}

	again := Decide(item.Version, opts, next, s.now())
	return s.apply(ctx, item, opts, next, again, false)
}

func (s *Syncer) install(ctx context.Context, item protocol.Item, opts protocol.AppOptions, st state.AppState) error {
	v, err := s.Client.FetchApp(ctx, item.ID, item.Version)
	if err != nil {
		return fmt.Errorf("fetch app: %w", err)
	}
	inst, why := s.installerFor(v)
	if why != nil {
		return s.reportUnavailable(ctx, item, opts, st, why)
	}

	// An upgrade whose installer can't replace the old version in place
	// removes it first, with that version's own uninstall -- but only a
	// version this agent installed.
	if v.UninstallPrevious && st.InstalledByAgent != 0 && st.InstalledByAgent != item.Version {
		prev, err := s.Client.FetchApp(ctx, item.ID, st.InstalledByAgent)
		if err != nil {
			return fmt.Errorf("fetch version %d to remove it: %w", st.InstalledByAgent, err)
		}
		pinst, why := s.installerFor(prev)
		if why != nil {
			return s.reportUnavailable(ctx, item, opts, st, why)
		}
		removeCtx, cancel := context.WithTimeout(ctx, opts.Timeout())
		started := s.now()
		r := pinst.Uninstall(removeCtx, item.ID, prev)
		cancel()
		if r.Err == nil && !r.TimedOut && pinst.Outcome(prev, r.ExitCode) == OutcomeFailed {
			r.Err = fmt.Errorf("removing version %d first failed with exit code %d", st.InstalledByAgent, r.ExitCode)
		} else if r.Err != nil {
			r.Err = fmt.Errorf("removing version %d first: %w", st.InstalledByAgent, r.Err)
		}
		if r.Err != nil || r.TimedOut {
			return s.finish(ctx, item, opts, st, protocol.IntentInstall, "", r, OutcomeFailed, started, s.now())
		}
		st.InstalledByAgent = 0
	}

	installCtx, cancel := context.WithTimeout(ctx, opts.Timeout())
	started := s.now()
	r := inst.Install(installCtx, item.ID, v)
	cancel()
	finished := s.now()

	outcome := inst.Outcome(v, r.ExitCode)
	installedVersion := ""
	if r.Err == nil && !r.TimedOut {
		switch outcome {
		case OutcomeSucceeded, OutcomeRebootRequired:
			// winget install does not report the version it landed; winget
			// list does, and a package's detection rule may.
			if _, ver, dr := inst.Detect(ctx, item.ID, v); dr.Err == nil {
				installedVersion = ver
			}
		}
	}
	return s.finish(ctx, item, opts, st, protocol.IntentInstall, installedVersion, r, outcome, started, finished)
}

func (s *Syncer) uninstall(ctx context.Context, item protocol.Item, opts protocol.AppOptions, st state.AppState) error {
	v, err := s.Client.FetchApp(ctx, item.ID, item.Version)
	if err != nil {
		return fmt.Errorf("fetch app: %w", err)
	}
	inst, why := s.installerFor(v)
	if why != nil {
		return s.reportUnavailable(ctx, item, opts, st, why)
	}

	uninstallCtx, cancel := context.WithTimeout(ctx, opts.Timeout())
	started := s.now()
	r := inst.Uninstall(uninstallCtx, item.ID, v)
	cancel()
	finished := s.now()

	return s.finish(ctx, item, opts, st, protocol.IntentUninstall, "", r, inst.Outcome(v, r.ExitCode), started, finished)
}

// finish turns an install or uninstall outcome into what to remember locally
// and what to report, in that order: state is written before the result is
// reported, so a server that cannot be reached does not make the agent try
// again on the next check-in.
func (s *Syncer) finish(ctx context.Context, item protocol.Item, opts protocol.AppOptions, st state.AppState,
	intent, installedVersion string, r Result, outcome Outcome, started, finished time.Time) error {

	result := protocol.AppResult{
		Version: item.Version, Intent: intent,
		InstalledVersion: installedVersion,
		ExitCode:         r.ExitCode,
		Stdout:           r.Stdout, Stderr: r.Stderr,
		StdoutTruncated: r.OutCut, StderrTruncated: r.ErrCut,
		StartedAt: started, FinishedAt: finished,
	}

	switch {
	case r.TimedOut:
		result.Status, result.ExitCode, result.Error = protocol.ResultFailed, -1, fmt.Sprintf("timed out after %s", opts.Timeout())
	case r.Err != nil:
		result.Status, result.ExitCode, result.Error = protocol.ResultFailed, -1, r.Err.Error()
	default:
		switch outcome {
		case OutcomeRebootRequired:
			result.Status = protocol.ResultSucceeded
			result.Detail = "a restart is needed to finish installing this app"
		case OutcomeSucceeded:
			result.Status = protocol.ResultSucceeded
		default:
			result.Status = protocol.ResultFailed
		}
	}

	next := st
	next.Version, next.Intent = item.Version, opts.Intent
	next.LastActedAt = finished
	next.LastStatus = result.Status

	if result.Status == protocol.ResultSucceeded {
		next.Failures = 0
		next.Installed = intent == protocol.IntentInstall
		next.LastSeenAt = finished
		next.InstalledByAgent = 0
		if next.Installed {
			next.InstalledByAgent = item.Version
		}
		// This report is itself the transition into the settled state, so a
		// later hourly detect that confirms the same thing must stay quiet.
		next.Settled = true
	} else if st.Version == item.Version && st.Intent == opts.Intent {
		next.Failures = st.Failures + 1
		next.Settled = false
	} else {
		next.Failures = 1
		next.Settled = false
	}

	if err := s.State.SetAppState(item.ID, next); err != nil {
		return fmt.Errorf("record local state: %w", err)
	}
	if err := s.Client.ReportAppResult(ctx, item.ID, result); err != nil {
		return fmt.Errorf("report result: %w", err)
	}
	return nil
}
