// Package scripts decides when an assigned script should run on this device,
// runs it, and reports what happened.
package scripts

import (
	"time"

	"retune/internal/agent/state"
	"retune/internal/agent/winsession"
	"retune/internal/protocol"
)

// Decision is what the scheduler concluded about one assigned script.
type Decision struct {
	Run bool
	// Reason explains a decision not to run, for the agent's log.
	Reason string
}

// Decide reports whether an assigned script should run now. It is deliberately
// a pure function: every rule is decided from the version, the options, what
// the agent remembers and the clock, so all of it is testable without a
// database, a filesystem, or a real script.
func Decide(version int, opts protocol.DeploymentOptions, st state.ItemState, now time.Time) Decision {
	if opts.NeedsUserSession() {
		if ok, reason := userSession(); !ok {
			// It applies to this device but there is nobody to run it as. The
			// server reports that as pending, from what the check-in told it.
			return Decision{Reason: reason}
		}
	}

	if st.LastRunAt.IsZero() {
		return Decision{Run: true}
	}

	if st.Version != version {
		if opts.RerunOnNewVersion {
			// A new version is a fresh attempt at the problem, so the failures
			// of the old one do not hold it back.
			return Decision{Run: true}
		}
		return Decision{Reason: "a new version is available but rerun_on_new_version is off"}
	}

	// Same version from here on, so consecutive failures count against it.
	if st.Failures > 0 && st.Failures >= opts.MaxRetries {
		return Decision{Reason: "this version has failed too many times"}
	}

	if opts.Frequency == protocol.FrequencyRecurring {
		if now.Sub(st.LastRunAt) >= opts.Interval() {
			return Decision{Run: true}
		}
		return Decision{Reason: "it is not due again yet"}
	}
	return Decision{Reason: "it has already run"}
}

// userSession reports whether a deployment that needs a signed-in user can run
// here. It is a variable so tests can decide without a real session.
var userSession = winsession.Available
