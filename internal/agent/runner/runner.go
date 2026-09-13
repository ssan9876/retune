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
	"time"

	"retune/internal/agent/agentcfg"
	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
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

	sess, err := session.New(session.Config{
		Identity:  id,
		IDStore:   idStore,
		State:     st,
		Collector: inventory.NewCollector(),
		Executor: &executor.Executor{
			Runner:    executor.DefaultRunner(filepath.Join(opts.DataDir, "scripts")),
			Restarter: executor.DefaultRestarter(),
			Now:       time.Now,
		},
		Log: opts.Log,
	})
	if err != nil {
		return err
	}
	sess.Start(ctx)

	loop := &checkin.Loop{Client: sess, Facts: facts.Checkin, Log: opts.Log, Rand: rand.Float64}
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
