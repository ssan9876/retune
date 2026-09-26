package selfupdate_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"retune/internal/agent/selfupdate"
)

// The test binary is an executable for this machine, so it must pass; the
// same file must fail for any other operating system or processor, and
// arbitrary bytes must fail everywhere.
func TestCheckExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := selfupdate.CheckExecutable(self); err != nil {
		t.Fatalf("this test binary should pass: %v", err)
	}

	otherOS := map[string]string{"windows": "linux", "linux": "darwin", "darwin": "windows"}[runtime.GOOS]
	if otherOS != "" {
		if err := selfupdate.CheckExecutableFor(self, otherOS, runtime.GOARCH); !errors.Is(err, selfupdate.ErrWrongPlatform) {
			t.Errorf("a %s binary should not pass as %s: %v", runtime.GOOS, otherOS, err)
		}
	}
	otherArch := map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH]
	if otherArch != "" {
		if err := selfupdate.CheckExecutableFor(self, runtime.GOOS, otherArch); !errors.Is(err, selfupdate.ErrWrongPlatform) {
			t.Errorf("an %s binary should not pass as %s: %v", runtime.GOARCH, otherArch, err)
		}
	}

	junk := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(junk, []byte("new agent bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"windows", "darwin", "linux"} {
		if err := selfupdate.CheckExecutableFor(junk, goos, "amd64"); !errors.Is(err, selfupdate.ErrWrongPlatform) {
			t.Errorf("junk should not pass as %s: %v", goos, err)
		}
	}
}
