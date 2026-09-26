package protocol

import "strings"

// The platforms an agent build is made for, as GOOS-GOARCH. A version is
// uploaded once per platform; a device is handed the one that matches it.
const (
	PlatformWindowsAMD64    = "windows-amd64"
	PlatformDarwinARM64     = "darwin-arm64"
	PlatformDarwinAMD64     = "darwin-amd64"
	PlatformDarwinUniversal = "darwin-universal" // both Mac processors in one file
	PlatformLinuxAMD64      = "linux-amd64"
	PlatformLinuxARM64      = "linux-arm64"
)

// Platforms lists every platform a build can be uploaded for.
var Platforms = []string{
	PlatformWindowsAMD64, PlatformDarwinARM64, PlatformDarwinAMD64, PlatformDarwinUniversal,
	PlatformLinuxAMD64, PlatformLinuxARM64,
}

// ValidPlatform reports whether p is a platform a build can be uploaded for.
func ValidPlatform(p string) bool {
	for _, q := range Platforms {
		if p == q {
			return true
		}
	}
	return false
}

// DevicePlatform is the platform a device's builds are chosen for: what its
// agent reported, or, for an agent too old to report one, windows-amd64 when
// the device runs Windows -- every agent that could update itself before
// platforms existed was a Windows one. "" means unknown.
func DevicePlatform(reported, osVersion string) string {
	if reported != "" {
		return reported
	}
	if strings.Contains(osVersion, "Windows") {
		return PlatformWindowsAMD64
	}
	return ""
}

// BuildCandidates lists, best first, the builds that can run on a device of
// platform p: its own, and for a Mac of either processor a universal build.
func BuildCandidates(p string) []string {
	switch p {
	case "":
		return nil
	case PlatformDarwinARM64, PlatformDarwinAMD64:
		return []string{p, PlatformDarwinUniversal}
	}
	return []string{p}
}
