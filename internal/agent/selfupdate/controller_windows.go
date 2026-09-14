//go:build windows

package selfupdate

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// recoveryDelay is how long the service control manager waits before each
// restart attempt. It matches installService in cmd/retune-agent, so a
// service repointed by an update behaves the same as one freshly installed.
const recoveryDelay = 60 * time.Second

// recoveryResetAfter is how long the service must run before the control
// manager forgets earlier failures and starts the restart count over.
const recoveryResetAfter = 24 * time.Hour

// stopPollInterval is how often Stop re-checks the service state while
// waiting for it to stop, mirroring stopAndWait in cmd/retune-agent.
const stopPollInterval = 300 * time.Millisecond

// windowsController is the real ServiceController, backed by handles to the
// service control manager and the service itself.
type windowsController struct {
	m *mgr.Mgr
	s *mgr.Service
}

func newController(serviceName string) (ServiceController, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		m.Disconnect()
		return nil, fmt.Errorf("open service %q: %w", serviceName, err)
	}
	return &windowsController{m: m, s: s}, nil
}

// Close releases the handles opened by newController. It tolerates either
// handle being nil so a zero-value controller can be closed harmlessly.
func (c *windowsController) Close() error {
	if c.s != nil {
		c.s.Close()
	}
	if c.m != nil {
		return c.m.Disconnect()
	}
	return nil
}

// Config reports the service's current image and arguments. BinaryPathName
// is stored as a command line, not a bare path — a manually installed
// service quotes the path when it contains spaces and appends arguments
// after it — so it is split with DecomposeCommandLine rather than on spaces,
// which would break a path like "C:\Program Files\Retune\retune-agent.exe".
func (c *windowsController) Config() (binPath string, args []string, err error) {
	cfg, err := c.s.Config()
	if err != nil {
		return "", nil, err
	}
	parts, err := windows.DecomposeCommandLine(cfg.BinaryPathName)
	if err != nil {
		return "", nil, fmt.Errorf("parse the service's binary path %q: %w", cfg.BinaryPathName, err)
	}
	if len(parts) == 0 {
		return "", nil, nil
	}
	return parts[0], parts[1:], nil
}

// SetBinPath repoints the service, quoting binPath and reattaching args with
// ComposeCommandLine — the inverse of Config's split — so a path containing
// spaces survives the round trip.
func (c *windowsController) SetBinPath(binPath string, args []string) error {
	cfg, err := c.s.Config()
	if err != nil {
		return err
	}
	cfg.BinaryPathName = windows.ComposeCommandLine(append([]string{binPath}, args...))
	if err := c.s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("set the service's binary path: %w", err)
	}
	return nil
}

// SetRecoveryActions arranges restarts on failure. A WiX-installed service
// has no recovery actions of its own, so without this a build that crashes
// immediately after an update would fail once and simply stay stopped.
func (c *windowsController) SetRecoveryActions() error {
	restarts := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: recoveryDelay},
		{Type: mgr.ServiceRestart, Delay: recoveryDelay},
		{Type: mgr.ServiceRestart, Delay: recoveryDelay},
	}
	if err := c.s.SetRecoveryActions(restarts, uint32(recoveryResetAfter.Seconds())); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	return nil
}

// Stop asks the service to stop and polls until it does, or ctx is done.
func (c *windowsController) Stop(ctx context.Context) error {
	st, err := c.s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := c.s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop the service: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(stopPollInterval):
		}
		st, err := c.s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
}

// Start starts the service.
func (c *windowsController) Start() error {
	if err := c.s.Start(); err != nil {
		return fmt.Errorf("start the service: %w", err)
	}
	return nil
}

// Running reports whether the service is currently running.
func (c *windowsController) Running() (bool, error) {
	st, err := c.s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running, nil
}
