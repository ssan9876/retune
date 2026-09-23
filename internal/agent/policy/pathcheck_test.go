package policy_test

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

func linkFileSetting(path, content string) protocol.Setting {
	return protocol.Setting{
		Kind: protocol.KindFile, Path: path, Ensure: protocol.EnsurePresent,
		ContentBase64: base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

// assertRefusedThrough checks every file operation refuses a path that runs
// through link, and that nothing reached target.
func assertRefusedThrough(t *testing.T, link, target string) {
	t.Helper()
	ctx := context.Background()
	h := policy.FileHandler{}
	s := linkFileSetting(filepath.Join(link, "planted.txt"), "owned")

	if _, err := h.Get(ctx, s); !errors.Is(err, policy.ErrLinkInPath) {
		t.Errorf("Get = %v", err)
	}
	if _, err := h.Test(ctx, s); !errors.Is(err, policy.ErrLinkInPath) {
		t.Errorf("Test = %v", err)
	}
	if err := h.Set(ctx, s); !errors.Is(err, policy.ErrLinkInPath) {
		t.Errorf("Set = %v", err)
	}
	if err := h.Revert(ctx, s, policy.State{}); !errors.Is(err, policy.ErrLinkInPath) {
		t.Errorf("Revert = %v", err)
	}
	absent := s
	absent.Ensure = protocol.EnsureAbsent
	if err := h.Set(ctx, absent); !errors.Is(err, policy.ErrLinkInPath) {
		t.Errorf("Set absent = %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "planted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file reached the link's target: %v", err)
	}
}

func TestFileSettingsRefuseAJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are Windows'")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "protected")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "innocent")
	// A junction needs no privilege to make, which is what makes it the
	// realistic attack.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	assertRefusedThrough(t, link, target)

	// A junction deeper down, under a real folder, is caught too.
	nested := filepath.Join(dir, "real")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(nested, "hop")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", deep, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	assertRefusedThrough(t, deep, target)
}

func TestFileSettingsRefuseASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "protected")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "innocent")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("can't make a symbolic link here: %v", err)
	}
	assertRefusedThrough(t, link, target)
}

func TestFileSettingsStillWriteOrdinaryPaths(t *testing.T) {
	ctx := context.Background()
	h := policy.FileHandler{}
	// A path whose folders don't exist yet: created, then written.
	path := filepath.Join(t.TempDir(), "a", "b", "c.txt")
	s := linkFileSetting(path, "hello")
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("Test = %v, %v", ok, err)
	}
}
