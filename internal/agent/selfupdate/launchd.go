package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Runner runs a command and returns its combined output. It is how the unix
// controllers reach launchctl, plutil and systemctl, and what a test replaces.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// LaunchdController is the ServiceController for the macOS launchd daemon.
// The daemon's plist is the equivalent of a Windows service's configuration:
// ProgramArguments[0] is the binary, and the rest are its arguments.
type LaunchdController struct {
	Label string // com.retune.agent
	Plist string // /Library/LaunchDaemons/com.retune.agent.plist
	Run   Runner
	// Poll is how often Stop re-checks that the daemon is gone; default 300ms.
	Poll time.Duration
}

func (c *LaunchdController) target() string { return "system/" + c.Label }

// Config reads ProgramArguments from the plist. plutil converts it to JSON,
// which is simpler and safer than parsing plist XML by hand, and it also
// reads a plist an MDM or an administrator rewrote in binary form.
func (c *LaunchdController) Config() (string, []string, error) {
	out, err := c.Run(context.Background(), "/usr/bin/plutil", "-extract", "ProgramArguments", "json", "-o", "-", c.Plist)
	if err != nil {
		return "", nil, fmt.Errorf("read ProgramArguments from %s: %w: %s", c.Plist, err, strings.TrimSpace(string(out)))
	}
	var argv []string
	if err := json.Unmarshal(out, &argv); err != nil {
		return "", nil, fmt.Errorf("parse ProgramArguments from %s: %w", c.Plist, err)
	}
	if len(argv) == 0 {
		return "", nil, fmt.Errorf("%s has no ProgramArguments", c.Plist)
	}
	return argv[0], argv[1:], nil
}

// SetBinPath rewrites ProgramArguments in place, leaving every other key of
// the plist -- KeepAlive, the log path, anything an administrator added --
// as it was.
func (c *LaunchdController) SetBinPath(binPath string, args []string) error {
	argv, err := json.Marshal(append([]string{binPath}, args...))
	if err != nil {
		return err
	}
	if out, err := c.Run(context.Background(), "/usr/bin/plutil", "-replace", "ProgramArguments", "-json", string(argv), c.Plist); err != nil {
		return fmt.Errorf("rewrite ProgramArguments in %s: %w: %s", c.Plist, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetRecoveryActions has nothing to do: the plist the agent installs sets
// KeepAlive, so launchd already restarts a build that crashes.
func (c *LaunchdController) SetRecoveryActions() error { return nil }

// Stop unloads the daemon and waits until launchd no longer knows it. bootout
// rather than kill or kickstart: with KeepAlive set, launchd would start a
// killed daemon straight back up on the old binary.
func (c *LaunchdController) Stop(ctx context.Context) error {
	if running, err := c.loaded(ctx); err != nil {
		return err
	} else if !running {
		return nil
	}
	if out, err := c.Run(ctx, "/bin/launchctl", "bootout", c.target()); err != nil {
		// bootout can report an error for a daemon that is already on its way
		// out; whether it is still loaded afterwards is what decides.
		if loaded, lerr := c.loaded(ctx); lerr == nil && !loaded {
			return nil
		}
		return fmt.Errorf("launchctl bootout %s: %w: %s", c.target(), err, strings.TrimSpace(string(out)))
	}
	poll := c.Poll
	if poll == 0 {
		poll = 300 * time.Millisecond
	}
	for {
		loaded, err := c.loaded(ctx)
		if err != nil {
			return err
		}
		if !loaded {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Start loads the daemon from its plist; RunAtLoad starts it. A daemon that is
// already loaded is started with kickstart instead, since bootstrap refuses it.
func (c *LaunchdController) Start() error {
	ctx := context.Background()
	// A daemon an administrator disabled stays disabled across bootstrap.
	_, _ = c.Run(ctx, "/bin/launchctl", "enable", c.target())
	out, err := c.Run(ctx, "/bin/launchctl", "bootstrap", "system", c.Plist)
	if err == nil {
		return nil
	}
	if loaded, lerr := c.loaded(ctx); lerr == nil && loaded {
		if kout, kerr := c.Run(ctx, "/bin/launchctl", "kickstart", c.target()); kerr != nil {
			return fmt.Errorf("launchctl kickstart %s: %w: %s", c.target(), kerr, strings.TrimSpace(string(kout)))
		}
		return nil
	}
	return fmt.Errorf("launchctl bootstrap %s: %w: %s", c.Plist, err, strings.TrimSpace(string(out)))
}

// Running reports whether the daemon is loaded and its process is running.
func (c *LaunchdController) Running() (bool, error) {
	out, err := c.Run(context.Background(), "/bin/launchctl", "print", c.target())
	if err != nil {
		// print fails for a daemon launchd does not know: not running.
		return false, nil
	}
	return strings.Contains(string(out), "state = running"), nil
}

// loaded reports whether launchd knows the daemon at all, running or not.
func (c *LaunchdController) loaded(ctx context.Context) (bool, error) {
	_, err := c.Run(ctx, "/bin/launchctl", "print", c.target())
	return err == nil, nil
}

// Close has nothing to release: every call runs its own command.
func (c *LaunchdController) Close() error { return nil }
