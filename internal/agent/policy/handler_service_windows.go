//go:build windows

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"retune/internal/protocol"
)

// ServiceHandler manages a Windows service's startup type and running state.
type ServiceHandler struct{}

func (ServiceHandler) Kind() string { return protocol.KindService }

// serviceState is a service as it was found.
type serviceState struct {
	Startup string `json:"startup"`
	State   string `json:"state"`
}

// openService connects to the service control manager and opens one service.
func openService(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connect to the service control manager: %w", err)
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		return nil, nil, fmt.Errorf("open the %s service: %w", name, err)
	}
	return m, s, nil
}

func startupName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return protocol.StartupAutomatic
	case mgr.StartManual:
		return protocol.StartupManual
	case mgr.StartDisabled:
		return protocol.StartupDisabled
	}
	return ""
}

func startupValue(name string) (uint32, bool) {
	switch name {
	case protocol.StartupAutomatic:
		return mgr.StartAutomatic, true
	case protocol.StartupManual:
		return mgr.StartManual, true
	case protocol.StartupDisabled:
		return mgr.StartDisabled, true
	}
	return 0, false
}

func (ServiceHandler) Get(_ context.Context, s protocol.Setting) (State, error) {
	m, service, err := openService(s.Name)
	if err != nil {
		// A service that is not installed has no state to restore.
		return State{}, nil
	}
	defer m.Disconnect()
	defer service.Close()

	cfg, err := service.Config()
	if err != nil {
		return State{}, err
	}
	status, err := service.Query()
	if err != nil {
		return State{}, err
	}
	running := protocol.StateStopped
	if status.State == svc.Running || status.State == svc.StartPending {
		running = protocol.StateRunning
	}
	raw, err := json.Marshal(serviceState{Startup: startupName(cfg.StartType), State: running})
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (ServiceHandler) Test(_ context.Context, s protocol.Setting) (bool, error) {
	m, service, err := openService(s.Name)
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	defer service.Close()

	if s.Startup != "" {
		cfg, err := service.Config()
		if err != nil {
			return false, err
		}
		if startupName(cfg.StartType) != s.Startup {
			return false, nil
		}
	}
	if s.State != "" {
		status, err := service.Query()
		if err != nil {
			return false, err
		}
		running := status.State == svc.Running
		if (s.State == protocol.StateRunning) != running {
			return false, nil
		}
	}
	return true, nil
}

func (ServiceHandler) Set(ctx context.Context, s protocol.Setting) error {
	m, service, err := openService(s.Name)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer service.Close()

	if s.Startup != "" {
		want, ok := startupValue(s.Startup)
		if !ok {
			return fmt.Errorf("unsupported startup type %q", s.Startup)
		}
		cfg, err := service.Config()
		if err != nil {
			return err
		}
		if cfg.StartType != want {
			cfg.StartType = want
			if err := service.UpdateConfig(cfg); err != nil {
				return fmt.Errorf("set the startup type: %w", err)
			}
		}
	}

	switch s.State {
	case protocol.StateRunning:
		return startService(ctx, service)
	case protocol.StateStopped:
		return stopService(ctx, service)
	}
	return nil
}

func startService(ctx context.Context, service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	if status.State != svc.StartPending {
		if err := service.Start(); err != nil {
			return fmt.Errorf("start the service: %w", err)
		}
	}
	return waitFor(ctx, service, svc.Running)
}

func stopService(ctx context.Context, service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop the service: %w", err)
		}
	}
	return waitFor(ctx, service, svc.Stopped)
}

// waitFor polls until the service reaches a state, or gives up. Services do not
// start or stop instantly, and reporting before it settled would be guessing.
func waitFor(ctx context.Context, service *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("the service did not reach the wanted state within 30 seconds")
}

// Revert puts the startup type and running state back as they were.
func (h ServiceHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if !prior.Exists || len(prior.Data) == 0 {
		// It was not installed, or its state was never recorded. Installing or
		// guessing would be worse than leaving it.
		return nil
	}
	var was serviceState
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	return h.Set(ctx, protocol.Setting{
		Kind: protocol.KindService, Name: s.Name, Startup: was.Startup, State: was.State,
	})
}
