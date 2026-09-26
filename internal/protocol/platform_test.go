package protocol_test

import (
	"strings"
	"testing"

	"retune/internal/protocol"
)

func TestDevicePlatform(t *testing.T) {
	for _, c := range []struct{ reported, os, want string }{
		{"darwin-arm64", "macOS 14.5", "darwin-arm64"},
		{"linux-amd64", "", "linux-amd64"},
		// Older agents report nothing: a Windows one is windows-amd64, the
		// only platform that could update itself then.
		{"", "Microsoft Windows 11 Enterprise 10.0.22631", "windows-amd64"},
		{"", "Windows 10 Pro (build 19045)", "windows-amd64"},
		{"", "macOS 14.5", ""},
	} {
		if got := protocol.DevicePlatform(c.reported, c.os); got != c.want {
			t.Errorf("DevicePlatform(%q, %q) = %q, want %q", c.reported, c.os, got, c.want)
		}
	}
}

func TestBuildCandidates(t *testing.T) {
	for p, want := range map[string]string{
		"darwin-arm64":  "darwin-arm64 darwin-universal",
		"darwin-amd64":  "darwin-amd64 darwin-universal",
		"windows-amd64": "windows-amd64",
		"linux-arm64":   "linux-arm64",
		"":              "",
	} {
		if got := strings.Join(protocol.BuildCandidates(p), " "); got != want {
			t.Errorf("BuildCandidates(%q) = %q, want %q", p, got, want)
		}
	}
	if protocol.ValidPlatform("darwin-universal") != true || protocol.ValidPlatform("freebsd-amd64") {
		t.Error("ValidPlatform")
	}
}
