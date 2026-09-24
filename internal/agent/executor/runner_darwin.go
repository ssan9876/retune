//go:build darwin

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

// DefaultRunner runs scripts through PowerShell 7 (pwsh), so the same script
// can be assigned to Windows and Mac devices. macOS does not ship pwsh; a
// Mac without it fails each script with an error saying so.
func DefaultRunner(scriptDir string) Runner { return PwshRunner{ScriptDir: scriptDir} }

// DefaultRestarter reboots with shutdown(8).
func DefaultRestarter() Restarter { return ShutdownRestarter{} }

// PwshRunner executes scripts from a file with PowerShell 7.
type PwshRunner struct {
	ScriptDir string
}

// pwshPaths are where the PowerShell package and Homebrew install pwsh. The
// agent runs under launchd with a minimal PATH, so they are tried directly.
var pwshPaths = []string{"/usr/local/bin/pwsh", "/opt/homebrew/bin/pwsh", "/usr/local/microsoft/powershell/7/pwsh"}

// errNoPwsh says what to install rather than just that a file is missing.
var errNoPwsh = errors.New("PowerShell 7 (pwsh) is not installed on this Mac; install it to run scripts")

func findPwsh() (string, error) {
	if p, err := exec.LookPath("pwsh"); err == nil {
		return p, nil
	}
	for _, p := range pwshPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errNoPwsh
}

func (r PwshRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	pwsh, err := findPwsh()
	if err != nil {
		return -1, err
	}
	if err := os.MkdirAll(r.ScriptDir, 0o700); err != nil {
		return -1, err
	}
	f, err := os.CreateTemp(r.ScriptDir, "cmd-*.ps1")
	if err != nil {
		return -1, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return -1, err
	}
	if err := f.Close(); err != nil {
		return -1, err
	}

	cmd := exec.CommandContext(ctx, pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", f.Name())
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Do not hang forever on a child that keeps the pipes open after a kill.
	cmd.WaitDelay = 5 * time.Second

	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), nil
	case err != nil:
		return -1, fmt.Errorf("run pwsh: %w", err)
	}
	return 0, nil
}

// ShutdownRestarter schedules a reboot. shutdown(8) counts in minutes, so a
// delay is rounded up to the next whole one; the message goes to logged-in
// users' terminals, not to a dialog.
type ShutdownRestarter struct{}

func (ShutdownRestarter) Restart(delay time.Duration, message string) error {
	when := "now"
	if delay > 0 {
		when = "+" + strconv.Itoa(int((delay+time.Minute-1)/time.Minute))
	}
	args := []string{"-r", when}
	if message != "" {
		args = append(args, message)
	}
	out, err := exec.Command("/sbin/shutdown", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schedule restart: %w: %s", err, out)
	}
	return nil
}
