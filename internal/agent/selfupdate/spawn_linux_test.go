//go:build linux

package selfupdate_test

import (
	"strings"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// The supervisor gets a transient unit of its own, so stopping the agent's
// unit cannot take it down, and it is told the agent's data directory.
func TestSystemdRunArgs(t *testing.T) {
	got := strings.Join(selfupdate.SystemdRunArgs("/var/lib/retune/supervisor", "/var/lib/retune", time.Unix(1700000000, 0)), " ")
	want := "--unit retune-agent-update-1700000000 --collect --quiet --no-block -- /var/lib/retune/supervisor supervise-update --data-dir /var/lib/retune"
	if got != want {
		t.Fatalf("systemd-run args:\n got %s\nwant %s", got, want)
	}
}
