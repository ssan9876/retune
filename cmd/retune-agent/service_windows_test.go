//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// secureDataDir hands the directory to Administrators, which only an elevated
// process may do. CI's Windows runner is elevated; a developer's everyday
// prompt usually is not, and these tests say so rather than fail.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("securing the data directory needs an elevated process")
	}
}

// Every path that puts something sensitive in the data directory calls this,
// and most of them call it on a directory that has already been secured, so
// it has to be safe to repeat. It also has to be safe to call before the
// directory exists: enroll and install both run before anything has created
// it.
func TestSecureDataDirIsIdempotentAndCreatesTheDirectory(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "Retune")

	if err := secureDataDir(dir); err != nil {
		t.Fatalf("securing a directory that does not exist yet: %v", err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("the directory should exist afterwards: %v", err)
	}
	if err := secureDataDir(dir); err != nil {
		t.Fatalf("securing an already secured directory: %v", err)
	}
}

// A directory somebody prepared before the agent got there - with an extra
// grant of their own, a junction pointing elsewhere, and a file carrying its
// own permissions - comes out with SYSTEM and Administrators alone, the
// junction gone, and whatever it pointed at untouched.
func TestSecureDataDirUndoesAPreparedDirectory(t *testing.T) {
	requireElevated(t)
	root := t.TempDir()
	dir := filepath.Join(root, "Retune")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	victim := filepath.Join(outside, "important.txt")
	if err := os.WriteFile(victim, []byte("leave me alone"), 0o644); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(planted, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	icaclsOrCmd(t, "icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)F")
	icaclsOrCmd(t, "icacls", planted, "/grant", "*S-1-1-0:F")
	icaclsOrCmd(t, "cmd", "/c", "mklink", "/J", filepath.Join(dir, "bin"), outside)

	if err := secureDataDir(dir); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{dir, planted} {
		if acl := icaclsOrCmd(t, "icacls", path); strings.Contains(acl, "Everyone") || strings.Contains(acl, "S-1-1-0") {
			t.Errorf("Everyone should have no access to %s any more:\n%s", path, acl)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "bin")); !os.IsNotExist(err) {
		t.Errorf("the junction should be gone, got %v", err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "leave me alone" {
		t.Errorf("what the junction pointed at must be untouched: %q %v", b, err)
	}
}

func icaclsOrCmd(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return string(out)
}
