// Package runner hosts the agent's check-in loop, independent of how the
// process was started: a terminal and the Windows service both call Run.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"path/filepath"
	"runtime"
	"time"

	"retune/internal/agent/agentcfg"
	"retune/internal/agent/apps"
	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/policy"
	"retune/internal/agent/scripts"
	"retune/internal/agent/selfupdate"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
	"retune/internal/agent/winupdate"
)

// Options configures one run of the agent.
type Options struct {
	DataDir string
	// Once checks in a single time and returns.
	Once bool
	Log  *slog.Logger
	// Out receives human-readable progress. Nil under the service, which has
	// no console to write to.
	Out io.Writer
}

// Run checks in until ctx is cancelled. It returns checkin.ErrUnenrolled if
// the server has unenrolled this device, after the local identity and state
// have been removed; the caller decides what that means, because a person at
// a terminal wants a message and a service wants to disable itself.
func Run(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		return errors.New("runner: Log is required")
	}
	idStore := identity.Store{Dir: opts.DataDir, Keys: identity.DefaultKeys()}
	id, err := idStore.Load()
	if errors.Is(err, identity.ErrNotEnrolled) {
		id, err = enrollFromConfig(ctx, opts, idStore)
	}
	if err != nil {
		return err
	}

	st, err := state.Open(filepath.Join(opts.DataDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	scriptRunner := executor.DefaultRunner(filepath.Join(opts.DataDir, "scripts"))

	// Whatever a previous attempt left behind is settled before the first
	// check-in. A rollback is only visible to the server if the restored agent
	// says so -- the supervisor cannot report it, because by the time it
	// decides, the agent it was testing is gone and the one that comes back is
	// this process -- and an attempt whose supervisor died is nobody's to
	// resolve unless this process does it.
	var rollback *selfupdate.Record
	if rec, found, err := selfupdate.ReadRecord(opts.DataDir); err != nil {
		opts.Log.Warn("could not read the self-update record", "error", err)
	} else {
		switch selfupdate.Reconcile(rec, found, facts.AgentVersion, time.Now()) {
		case selfupdate.ReconcileReport:
			opts.Log.Warn("a previous update was rolled back",
				"attempted", rec.ToVersion, "restored", rec.FromVersion, "detail", rec.Detail)
			rollback = &rec
		case selfupdate.ReconcileAbandon:
			opts.Log.Warn("abandoning an expired update attempt",
				"from", rec.FromVersion, "to", rec.ToVersion)
			if err := selfupdate.RemoveRecord(opts.DataDir); err != nil {
				opts.Log.Warn("could not remove the expired update record", "error", err)
			}
		}
	}

	// A machine with no App Installer simply cannot deploy apps; every other
	// part of the agent still works, so this must not stop it from starting.
	// The syncer is still built, though: an assigned app must be reported
	// failed, plainly, rather than the device just going silent about it.
	appSyncer := &apps.Syncer{State: st, Log: opts.Log, Now: time.Now, Operations: facts.Operations()}
	if wg, err := apps.New(); err != nil {
		opts.Log.Info("app deployments are unavailable on this machine", "error", err)
		appSyncer.Unavailable = err
	} else {
		appSyncer.Winget = wg
	}
	// Uploaded packages need no App Installer, only Windows. Their download
	// client is filled in by the session.
	if pk, err := apps.NewPackages(filepath.Join(opts.DataDir, "app-cache"), nil); err != nil {
		appSyncer.PackagesUnavailable = err
	} else {
		appSyncer.Packages = pk
	}

	updater := &selfupdate.Syncer{
		Dir: opts.DataDir, Running: facts.AgentVersion, Injected: facts.VersionInjected(),
		Trusted: facts.TrustedKeys(),
		Log:     opts.Log, Now: time.Now, Rollback: rollback,
		Spawn: func(path string) error { return selfupdate.SpawnSupervisor(path, opts.DataDir) },
		// The right version built for another machine is refused before the
		// service is touched.
		CheckExecutable: selfupdate.CheckExecutable,
	}
	// An agent not installed as a Windows service, launchd daemon or systemd
	// unit cannot self-update. Every assigned build is then refused with that
	// reason rather than the device going quiet about it.
	if control, err := selfupdate.NewController(selfupdate.ServiceName); err != nil {
		opts.Log.Info("self-update is unavailable on this machine", "error", err)
		updater.Unavailable = err
	} else {
		updater.Control = control
		// Run holds the controller for exactly as long as the syncer lives;
		// the handles go back to the service control manager when Run returns.
		defer control.Close()
	}

	// Windows Update is asked what it is offering at most daily: a search
	// can take minutes.
	var updates *winupdate.Cache
	if runtime.GOOS == "windows" {
		updates = &winupdate.Cache{Store: st, Runner: scriptRunner, Now: time.Now, MaxAge: 24 * time.Hour}
	}
	sess, err := session.New(session.Config{
		Identity:  id,
		IDStore:   idStore,
		State:     st,
		Collector: inventory.NewCollector(),
		Executor: &executor.Executor{
			Runner:     scriptRunner,
			Restarter:  executor.DefaultRestarter(),
			Now:        time.Now,
			Locker:     executor.DefaultLocker(),
			Wiper:      executor.DefaultWiper(scriptRunner),
			Passwords:  executor.DefaultPasswords(),
			Operations: facts.Operations(),
			DeviceID:   id.DeviceID,
			Logs: executor.LogSources{
				Dir: opts.DataDir, Channels: []string{"System", "Application"},
				Events: executor.DefaultEventExporter(),
			},
		},
		Scripts: &scripts.Scheduler{
			State: st, Runner: scriptRunner, Log: opts.Log, Now: time.Now,
			Operations: facts.Operations(),
		},
		Policy: &policy.Syncer{
			// Handlers are filled in by the session, which owns the client
			// the BitLocker handler escrows through.
			Reconciler: &policy.Reconciler{State: st, Log: opts.Log},
			Cache:      st, Log: opts.Log,
			Operations: facts.Operations(),
		},
		Apps:       appSyncer,
		SelfUpdate: updater,
		Updates:    updates,
		// Kept current for software on the device that gates access on
		// compliance, such as a zero-trust proxy.
		StatementPath: filepath.Join(opts.DataDir, "compliance.jwt"),
		Log:           opts.Log,
	})
	if err != nil {
		return err
	}
	sess.Start(ctx)

	loop := &checkin.Loop{Client: sess, Facts: facts.Checkin, Log: opts.Log, Rand: rand.Float64, Waiter: sess}
	if !opts.Once {
		return loop.Run(ctx)
	}

	wait, err := loop.RunOnce(ctx)
	if err != nil {
		return err
	}
	sess.Wait()
	if err := sess.FlushResults(ctx); err != nil {
		opts.Log.Warn("some results are still queued", "error", err)
	}
	if opts.Out != nil {
		fmt.Fprintf(opts.Out, "Check-in OK; next in %s\n", wait.Round(time.Second))
	}
	return nil
}

// enrollFromConfig enrolls a device that has settings but no identity yet,
// which is how a machine installed by the MSI comes up: the installer writes
// the settings, and the first start of the service turns them into an
// identity. The token is removed once it has been spent.
func enrollFromConfig(ctx context.Context, opts Options, idStore identity.Store) (*identity.Identity, error) {
	cfg, err := agentcfg.Load(opts.DataDir)
	if errors.Is(err, agentcfg.ErrNoConfig) {
		return nil, fmt.Errorf("this device is not enrolled and has no %s in %s; "+
			"run retune-agent enroll, or install the MSI with SERVER_URL and ENROLL_TOKEN",
			agentcfg.FileName, opts.DataDir)
	}
	if err != nil {
		return nil, err
	}
	if cfg.ServerURL == "" || cfg.EnrollToken == "" {
		return nil, fmt.Errorf("%s has no server_url or enroll_token, so this device cannot enroll",
			agentcfg.FileName)
	}

	opts.Log.Info("enrolling from the installed configuration", "server_url", cfg.ServerURL)
	id, err := enrollment.Enroll(ctx, enrollment.Options{
		ServerURL: cfg.ServerURL,
		Token:     cfg.EnrollToken,
		Pin:       cfg.ServerCertFingerprint,
		Facts:     facts.Device(),
		Store:     idStore,
	})
	if err != nil {
		return nil, err
	}
	// The token is spent, and it is a credential: keeping it on disk buys
	// nothing. A failure here must not kill a device that just enrolled.
	if err := agentcfg.ClearToken(opts.DataDir); err != nil {
		opts.Log.Warn("could not remove the spent enrollment token", "error", err)
	}
	opts.Log.Info("enrolled", "device_id", id.DeviceID)
	return id, nil
}
