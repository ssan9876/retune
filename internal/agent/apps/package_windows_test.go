//go:build windows

package apps

import (
	"strings"
	"testing"

	"retune/internal/protocol"
)

// TestWindowsProbe reads things every Windows machine has. It only reads.
func TestWindowsProbe(t *testing.T) {
	p := windowsProbe{}

	build, found, err := p.Registry(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuild")
	if err != nil || !found || build == "" {
		t.Fatalf("CurrentBuild = %q, %v, %v", build, found, err)
	}
	if _, found, err := p.Registry(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, ""); err != nil || !found {
		t.Fatalf("the key itself: %v, %v", found, err)
	}
	if _, found, err := p.Registry(`SOFTWARE\Retune\NoSuchKey`, ""); err != nil || found {
		t.Fatalf("a missing key: %v, %v", found, err)
	}
	if _, found, err := p.Registry(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "NoSuchValue"); err != nil || found {
		t.Fatalf("a missing value: %v, %v", found, err)
	}

	kernel := p.Expand(`%SystemRoot%\System32\kernel32.dll`)
	if strings.Contains(kernel, "%") {
		t.Fatalf("not expanded: %q", kernel)
	}
	version, found, err := p.FileVersion(kernel)
	if err != nil || !found {
		t.Fatalf("kernel32.dll: %v, %v", found, err)
	}
	if _, err := protocol.ParseVersion(version); err != nil {
		t.Fatalf("kernel32.dll version %q: %v", version, err)
	}
	if _, found, err := p.FileVersion(`C:\Retune\no-such-file.exe`); err != nil || found {
		t.Fatalf("a missing file: %v, %v", found, err)
	}

	installed, _, err := Detect(protocol.DetectionRule{
		Type: protocol.DetectFile, Path: `%SystemRoot%\System32\kernel32.dll`, VersionAtLeast: "6.0",
	}, p)
	if err != nil || !installed {
		t.Fatalf("detect kernel32.dll >= 6.0 = %v, %v", installed, err)
	}
}
