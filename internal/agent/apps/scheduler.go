package apps

import (
	"time"

	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// DetectEvery is how often an app that is already in the right state is
// checked again. Retune does not chase upstream releases, but it does notice
// when somebody has removed software that was assigned.
const DetectEvery = time.Hour

// maxAttempts is how many consecutive failures of one version, under one
// intent, are tolerated before Retune stops trying. A package that will not
// install is usually a problem with the package, not the machine, so
// retrying forever only fills the log.
const maxAttempts = 3

// Action is what the agent should do next about one assigned app.
type Action int

const (
	ActionNone Action = iota
	ActionDetect
	ActionInstall
	ActionUninstall
)

// Decision is what the scheduler concluded about one assigned app.
type Decision struct {
	Action Action
	// Reason explains a decision to do nothing, for the agent's log.
	Reason string
}

// Decide reports what to do about one assigned app. It is deliberately a pure
// function, as scripts.Decide is: every rule is decided from the version,
// the options, what the agent remembers and the clock, so all of it is
// testable without winget.
func Decide(version int, opts protocol.AppOptions, st state.AppState, now time.Time) Decision {
	// A new version or a changed intent is a fresh instruction, so neither the
	// old failures nor the old detection hold it back. Finding out whether the
	// software is actually present is the safer order before installing or
	// removing it, and it costs one cheap local `winget list`.
	fresh := st.Version != version || st.Intent != opts.Intent
	if fresh || st.LastSeenAt.IsZero() {
		return Decision{Action: ActionDetect}
	}

	if st.Failures > 0 && st.Failures >= maxAttempts {
		return Decision{Reason: "this version has failed too many times"}
	}

	want := opts.Intent == protocol.IntentInstall
	if st.Installed != want {
		if want {
			return Decision{Action: ActionInstall}
		}
		return Decision{Action: ActionUninstall}
	}

	if now.Sub(st.LastSeenAt) >= DetectEvery {
		return Decision{Action: ActionDetect}
	}
	return Decision{Reason: "it is already in the right state"}
}
