//go:build windows

package policy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// RunPowerShell executes a script and returns its standard output. Errors carry
// what PowerShell said, because "exit status 1" on its own helps nobody.
func RunPowerShell(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// RunNetsh runs netsh with args as the rest of its command line, exactly as
// given, and returns what it printed. netsh reports most failures on stdout,
// so that is included in the error too.
func RunNetsh(ctx context.Context, args string) (string, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	cmd := exec.CommandContext(ctx, exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "netsh " + args, HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("netsh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
