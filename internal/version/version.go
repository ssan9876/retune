// Package version is the version the server and its updater were built as.
package version

// DevVersion is what an unstamped build reports. It is lower than every
// release, so a development build is always offered the newest one.
const DevVersion = "0.0.0-dev"

// Version is stamped at build time:
//
//	go build -ldflags "-X retune/internal/version.Version=1.4.0" ./cmd/retune-server
var Version = DevVersion

// Stamped reports whether this build was given a real version.
func Stamped() bool { return Version != "" && Version != DevVersion }
