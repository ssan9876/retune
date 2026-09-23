//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"retune/internal/agent/checkin"
	"retune/internal/agent/logging"
	"retune/internal/agent/runner"
)

// serviceName is both the service name and the Event Log source.
const serviceName = "Retune"

// retryDelay is how long the service waits before starting the check-in loop
// again after a failure, such as a server that is not reachable yet or a
// machine that has been installed but not configured.
const retryDelay = 60 * time.Second

func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// runService hands control to the service control manager.
func runService(ctx context.Context, dataDir string) error {
	return svc.Run(serviceName, &handler{dataDir: dataDir})
}

type handler struct {
	dataDir string
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	log, closeLog, err := logging.New(logging.Options{Dir: h.dataDir, EventLog: true})
	if err != nil {
		// Nowhere to write about it: a service has no console.
		return true, 1
	}
	defer closeLog()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- h.serve(ctx, log) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done // let the session finish what it is doing
				return false, 0
			}
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			if errors.Is(err, checkin.ErrUnenrolled) {
				// The identity and state are already gone. Disable the service
				// so it does not restart into a machine that has no business
				// talking to the server; the MSI stays installed, so a new
				// token can re-enroll it.
				log.Warn("device was unenrolled; disabling the service")
				if err := disableService(); err != nil {
					log.Error("disable the service", "error", err)
				}
			} else if err != nil {
				log.Error("agent stopped", "error", err)
			}
			return false, 0
		}
	}
}

// serve runs the check-in loop, retrying anything short of unenrollment. A
// machine may be installed before the server is reachable, or configured
// minutes later; exiting would make the service control manager fight the
// process with restarts.
func (h *handler) serve(ctx context.Context, log *slog.Logger) error {
	// Before anything else reads or writes in there. The directory holds the
	// device key and, since self-update, binaries this service runs as
	// LocalSystem; if a standard user got there first, they own it and can
	// plant one. Starting anyway is the escalation, so this is the one failure
	// the service does not retry through.
	if err := secureDataDir(h.dataDir); err != nil {
		log.Error("could not restrict the data directory; refusing to start", "dir", h.dataDir, "error", err)
		return fmt.Errorf("securing %s: %w", h.dataDir, err)
	}

	for {
		err := runner.Run(ctx, runner.Options{DataDir: h.dataDir, Log: log})
		switch {
		case errors.Is(err, checkin.ErrUnenrolled):
			return err
		case ctx.Err() != nil:
			return nil
		case err != nil:
			log.Warn("agent run failed; retrying", "error", err, "retry_in", retryDelay)
		default:
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retryDelay):
		}
	}
}

// installService registers the service and its Event Log source. The state
// directory is recorded as an argument, because a service is started by the
// control manager with nothing else to go on.
func installService(exePath, dataDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return adminError(err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("the %s service is already installed", serviceName)
	}

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName:  "Retune Agent",
		Description:  "Reports inventory to the Retune server and runs assigned commands.",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl: mgr.ErrorNormal,
		// An empty account name means LocalSystem.
	}, "--data-dir", dataDir)
	if err != nil {
		return adminError(err)
	}
	defer s.Close()

	// Restart a few times on failure, then leave it alone; the daily reset
	// means a machine that fails once a week still keeps trying.
	restarts := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: retryDelay},
		{Type: mgr.ServiceRestart, Delay: retryDelay},
		{Type: mgr.ServiceRestart, Delay: retryDelay},
	}
	if err := s.SetRecoveryActions(restarts, uint32((24 * time.Hour).Seconds())); err != nil {
		s.Delete()
		return fmt.Errorf("set recovery actions: %w", err)
	}

	if err := registerEventLogSource(); err != nil {
		s.Delete()
		return err
	}
	return nil
}

// registerEventLogSource makes the Event Log render the agent's messages
// properly. Without it Windows invents a bare source and every entry is
// wrapped in "the description for Event ID 1 cannot be found".
func registerEventLogSource() error {
	err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("register the event log source: %w", err)
	}
	return nil
}

// removeEventLogSource deregisters the source, tolerating its absence.
func removeEventLogSource() error {
	if err := eventlog.Remove(serviceName); err != nil && !strings.Contains(err.Error(), "not exist") {
		return err
	}
	return nil
}

// uninstallService stops and removes the service, tolerating anything that is
// already gone.
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return adminError(err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the %s service is not installed", serviceName)
	}
	defer s.Close()

	if err := stopAndWait(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return adminError(err)
	}
	// The service is gone either way, which is what was asked for.
	_ = removeEventLogSource()
	return nil
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop the service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("the service did not stop within 30 seconds")
}

// disableService stops the service from starting again, used after the server
// has unenrolled this device.
func disableService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.StartType = mgr.StartDisabled
	return s.UpdateConfig(cfg)
}

// adminError explains the most common reason any of this fails.
func adminError(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	return err
}
