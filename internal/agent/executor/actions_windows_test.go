//go:build windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWevtutilExportsOnThisMachine exports the last hour of the Application
// log: read-only, to a temporary directory.
func TestWevtutilExportsOnThisMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Application.evtx")
	err := Wevtutil{}.Export(context.Background(), "Application", path, 1)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "access") {
		t.Skipf("this shell can't read the Application log: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("export = %v, %v", info, err)
	}
}
