//go:build !windows

package main

import (
	"context"
	"errors"
)

// The service control manager is Windows-only; on other platforms the agent
// runs in the foreground and is supervised by whatever started it.

func isWindowsService() bool { return false }

func runService(context.Context, string) error {
	return errors.New("the Retune service is only available on Windows; use retune-agent run")
}

func installService(string) error {
	return errors.New("service installation is only available on Windows")
}

func uninstallService() error {
	return errors.New("service removal is only available on Windows")
}

// secureDataDir is a no-op: the directory is already created with 0700.
func secureDataDir(string) error { return nil }

// There is no Event Log to register with away from Windows.
func registerEventLogSource() error { return nil }
func removeEventLogSource() error   { return nil }
