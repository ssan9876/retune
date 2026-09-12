//go:build windows

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// DefaultRunner runs scripts through powershell.exe, using scriptDir for the
// temporary .ps1 files.
func DefaultRunner(scriptDir string) Runner { return PowerShellRunner{ScriptDir: scriptDir} }

// DefaultRestarter reboots with shutdown.exe.
func DefaultRestarter() Restarter { return ShutdownRestarter{} }

// PowerShellRunner executes scripts from a file so any script length works.
type PowerShellRunner struct {
	ScriptDir string
}

// utf8BOM makes PowerShell 5.1 read a script file as UTF-8.
const utf8BOM = "\ufeff"

// utf8Preamble makes redirected output UTF-8 instead of the console codepage.
const utf8Preamble = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n" +
	"$OutputEncoding = [System.Text.Encoding]::UTF8\r\n"

func (r PowerShellRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	if err := os.MkdirAll(r.ScriptDir, 0o700); err != nil {
		return -1, err
	}
	f, err := os.CreateTemp(r.ScriptDir, "cmd-*.ps1")
	if err != nil {
		return -1, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(utf8BOM + utf8Preamble + script); err != nil {
		f.Close()
		return -1, err
	}
	if err := f.Close(); err != nil {
		return -1, err
	}

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f.Name())
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Do not hang forever on a child that keeps the pipes open after a kill.
	cmd.WaitDelay = 5 * time.Second

	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), nil
	case err != nil:
		return -1, fmt.Errorf("run powershell: %w", err)
	}
	return 0, nil
}

// ShutdownRestarter schedules a planned reboot.
type ShutdownRestarter struct{}

func (ShutdownRestarter) Restart(delay time.Duration, message string) error {
	args := []string{"/r", "/t", strconv.Itoa(int(delay.Seconds())), "/d", "p:0:0"}
	if message != "" {
		args = append(args, "/c", message)
	}
	out, err := exec.Command("shutdown.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schedule restart: %w: %s", err, out)
	}
	return nil
}
