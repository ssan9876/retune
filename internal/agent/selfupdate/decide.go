// Package selfupdate decides whether an agent should replace its own binary
// and records the attempt, so a supervisor process can restore the service
// if the new binary never checks in.
package selfupdate

// Action is what Decide concluded about the assigned version.
type Action int

const (
	ActionNone Action = iota
	ActionUpdate
)

// Decision is the outcome of Decide.
type Decision struct {
	Action Action
	// Reason explains a decision not to update, for the agent's log.
	Reason string
}

// Decide reports whether this agent should replace itself. It is deliberately
// a pure function: the running version, the assigned one, whether this build
// was stamped at all, and what was last attempted are the whole input.
func Decide(running, assigned string, injected bool, attempted Record) Decision {
	// A build that was never stamped reports the placeholder for ever. It
	// would update, report the same string, be told to update again, and do
	// that on every check-in on every machine. Refusing is the only safe
	// answer, and saying so is how somebody finds out why.
	if !injected {
		return Decision{Reason: "this build has no injected version, so it will not self-update"}
	}
	if assigned == "" {
		return Decision{Reason: "the assigned build has no version"}
	}
	// Difference, not ordering: assigning an older build is how a fleet is
	// recovered from a bad one.
	if running == assigned {
		return Decision{Reason: "this device is already running the assigned version"}
	}
	if attempted.ToVersion == assigned {
		switch attempted.Status {
		case StatusRolledBack:
			return Decision{Reason: "this version was already tried here and rolled back"}
		case StatusPending:
			return Decision{Reason: "an update to this version is already under way"}
		}
	}
	return Decision{Action: ActionUpdate}
}
