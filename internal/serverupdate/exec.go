package serverupdate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Cmd is one external command an Env runs: docker, systemctl, pg_dump.
type Cmd struct {
	Name string
	Args []string
	// Env is added to the process environment - how a database password
	// reaches pg_dump without appearing on its command line.
	Env []string
	// Stdout receives the command's output when set; otherwise Run returns it.
	Stdout io.Writer
}

func (c Cmd) String() string { return c.Name + " " + strings.Join(c.Args, " ") }

// Runner runs commands. Tests replace it; nothing in this package calls
// exec directly.
type Runner interface {
	Run(ctx context.Context, c Cmd) ([]byte, error)
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

// Run runs c and returns its output, or an error carrying what it printed to
// stderr, since "exit status 1" on its own tells nobody anything.
func (ExecRunner) Run(ctx context.Context, c Cmd) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
	}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", c.Name, err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}
