//go:build windows

package apps

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"retune/internal/agent/executor"
	"retune/internal/protocol"
)

// New resolves winget.exe. As LocalSystem, winget is not on PATH — a real
// probe of this machine found it only under %ProgramFiles%\WindowsApps, in
// the newest directory belonging to the Desktop App Installer package.
func New() (Winget, error) {
	root := filepath.Join(programFiles(), "WindowsApps")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, ErrNoAppInstaller
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() && isInstallerDir(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// Descending, so a side-by-side upgrade leaves the newest package tried
	// first.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	for _, name := range names {
		exe := filepath.Join(root, name, "winget.exe")
		if _, err := os.Stat(exe); err == nil {
			return &client{path: exe}, nil
		}
	}
	return nil, ErrNoAppInstaller
}

func programFiles() string {
	if v := os.Getenv("ProgramFiles"); v != "" {
		return v
	}
	return `C:\Program Files`
}

func isInstallerDir(name string) bool {
	return strings.HasPrefix(name, "Microsoft.DesktopAppInstaller_") &&
		strings.HasSuffix(name, "_x64__8wekyb3d8bbwe")
}

// client drives one resolved winget.exe.
type client struct{ path string }

func (c *client) Detect(ctx context.Context, packageID string) (bool, string, Result) {
	r := c.run(ctx, detectArgs(packageID))
	if classify(r.ExitCode) != OutcomeSucceeded {
		return false, "", r
	}
	return true, installedVersion(r.Stdout, packageID), r
}

func (c *client) Install(ctx context.Context, v protocol.AppVersionResponse) Result {
	return c.run(ctx, installArgs(v))
}

func (c *client) Uninstall(ctx context.Context, packageID string) Result {
	return c.run(ctx, uninstallArgs(packageID))
}

func (c *client) run(ctx context.Context, args []string) Result {
	stdout := executor.NewCapped(protocol.MaxOutputBytes)
	stderr := executor.NewCapped(protocol.MaxOutputBytes)

	cmd := exec.CommandContext(ctx, c.path, args...)
	// winget writes UTF-8 to a redirected pipe. Capped.String() decodes that
	// explicitly as UTF-8 rather than letting anything upstream reinterpret it
	// through the console's codepage, which is how a real probe turned "©"
	// into "┬⌐".
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	res := Result{
		Stdout: stdout.String(), Stderr: stderr.String(),
		OutCut: stdout.Truncated(), ErrCut: stderr.Truncated(),
	}

	var exitErr *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.TimedOut, res.Err, res.ExitCode = true, ctx.Err(), -1
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	case err != nil:
		res.Err, res.ExitCode = err, -1
	default:
		res.ExitCode = 0
	}
	return res
}
