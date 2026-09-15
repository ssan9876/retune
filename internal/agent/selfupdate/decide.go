// Package selfupdate decides whether an agent should replace its own binary
// and records the attempt, so a supervisor process can restore the service
// if the new binary never checks in.
package selfupdate

import "time"

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
	// Report says whether a refusal is a build defect worth shouting about:
	// no injected version, or no trusted release keys. Both would otherwise
	// refuse silently on every check-in on every affected machine, which is
	// how a bad build ships unnoticed. Every other refusal -- already
	// current, an in-flight or already-rolled-back attempt -- is routine and
	// must stay quiet; syncOne reports a refusal only when this is true,
	// rather than re-deriving which reasons count from the Reason string.
	Report bool
}

// Decide reports whether this agent should replace itself. It is deliberately
// a pure function: the running version, the assigned one, whether this build
// was stamped at all, how many release keys it trusts, and what was last
// attempted are the whole input.
func Decide(running, assigned string, injected bool, trusted int, attempted Record) Decision {
	// A build that was never stamped reports the placeholder for ever. It
	// would update, report the same string, be told to update again, and do
	// that on every check-in on every machine. Refusing is the only safe
	// answer, and saying so is how somebody finds out why.
	if !injected {
		return Decision{Reason: "this build has no injected version, so it will not self-update", Report: true}
	}
	if assigned == "" {
		return Decision{Reason: "the assigned build has no version"}
	}
	// Difference, not ordering: assigning an older build is how a fleet is
	// recovered from a bad one.
	if running == assigned {
		return Decision{Reason: "this device is already running the assigned version"}
	}
	// A build with no trusted release keys cannot verify anything it
	// downloads, so it must not download. Like the unstamped case, this is a
	// build problem, and saying so on every check-in is how it gets fixed.
	// Checked after the same-version comparison: a build already on its
	// assigned version must stay quiet rather than report "failed" every
	// cycle while the server's inference marks the device "succeeded" -- a
	// flapping status nobody could act on anyway, since there is nothing to
	// update to.
	if trusted == 0 {
		return Decision{Reason: "this build has no trusted release keys, so it will not self-update", Report: true}
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

// ReconcileAction is what a starting agent should do about the record it
// found on disk.
type ReconcileAction int

const (
	// ReconcileNone leaves the record exactly as it is.
	ReconcileNone ReconcileAction = iota
	// ReconcileReport is a rollback that only the restored agent can tell the
	// server about, because the supervisor that decided it is gone.
	ReconcileReport
	// ReconcileAbandon is a pending attempt with nobody left to resolve it.
	ReconcileAbandon
)

// Reconcile says what a starting agent should make of the record it found.
// Like Decide it is pure, so the rules can be read and tested without a
// runner, a data directory or a service around them.
func Reconcile(rec Record, found bool, running string, now time.Time) ReconcileAction {
	if !found {
		return ReconcileNone
	}
	switch rec.Status {
	case StatusRolledBack:
		// An already reported rollback stays on disk as the memory that this
		// version failed here, but there is nothing left to tell the server.
		if rec.Reported {
			return ReconcileNone
		}
		return ReconcileReport
	case StatusPending:
		// The staged build is the one running, so the attempt is still alive
		// even past its deadline: the supervisor may be dead, but CheckedIn
		// resolves it on the first check-in that reaches the server.
		if rec.ToVersion == running {
			return ReconcileNone
		}
		// The old build is back and the deadline has passed with no verdict
		// written, which means the supervisor never got to write one -- a
		// reboot, an MSI repair, something killed it. No verdict is invented
		// here either: for the same reason a cancelled supervision records
		// none, penalizing a build nobody ever judged is worse than retrying
		// it.
		if !now.Before(rec.Deadline) {
			return ReconcileAbandon
		}
	}
	return ReconcileNone
}
