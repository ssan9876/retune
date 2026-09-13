//go:build windows

package policy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
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
