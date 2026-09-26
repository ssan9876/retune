//go:build !windows

package selfupdate

import (
	"context"
	"os/exec"
)

// execRunner is the real Runner: the command's combined output, so a failure
// carries what the tool said.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
