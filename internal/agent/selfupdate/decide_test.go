package selfupdate_test

import (
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

func TestDecide(t *testing.T) {
	cases := map[string]struct {
		running, assigned string
		injected          bool
		trusted           int
		attempted         selfupdate.Record
		want              selfupdate.Action
		reason            string
		// report is what a refusal should set Decision.Report to: true only
		// for the two build-defect reasons, which is what tells syncOne
		// whether to report the refusal to the server or stay quiet.
		report bool
	}{
		"already on the assigned version": {
			running: "1.2.3", assigned: "1.2.3", injected: true, trusted: 1,
			want: selfupdate.ActionNone, reason: "already",
		},
		"a newer version is assigned": {
			running: "1.2.3", assigned: "1.3.0", injected: true, trusted: 1,
			want: selfupdate.ActionUpdate,
		},
		"an older version is assigned: a downgrade is a real instruction": {
			running: "1.3.0", assigned: "1.2.3", injected: true, trusted: 1,
			want: selfupdate.ActionUpdate,
		},
		"this build has no injected version": {
			running: "0.1.0-dev", assigned: "1.3.0", injected: false, trusted: 1,
			want: selfupdate.ActionNone, reason: "no injected version", report: true,
		},
		"this build trusts no release key": {
			running: "1.2.3", assigned: "1.3.0", injected: true, trusted: 0,
			want: selfupdate.ActionNone, reason: "no trusted release keys", report: true,
		},
		"already on the assigned version, and trusts no release key: staying quiet wins": {
			running: "1.2.3", assigned: "1.2.3", injected: true, trusted: 0,
			want: selfupdate.ActionNone, reason: "already running",
		},
		"the same version already failed and was rolled back": {
			running: "1.2.3", assigned: "1.3.0", injected: true, trusted: 1,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusRolledBack},
			want:      selfupdate.ActionNone, reason: "rolled back",
		},
		"a different version after a rollback is still attempted": {
			running: "1.2.3", assigned: "1.4.0", injected: true, trusted: 1,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusRolledBack},
			want:      selfupdate.ActionUpdate,
		},
		"an update is already in flight": {
			running: "1.2.3", assigned: "1.3.0", injected: true, trusted: 1,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusPending},
			want:      selfupdate.ActionNone, reason: "already under way",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := selfupdate.Decide(tc.running, tc.assigned, tc.injected, tc.trusted, tc.attempted)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v (reason %q)", got.Action, tc.want, got.Reason)
			}
			if got.Action == selfupdate.ActionNone && got.Reason == "" {
				t.Error("a decision not to update should say why, for the agent's log")
			}
			if got.Report != tc.report {
				t.Errorf("report = %v, want %v (reason %q)", got.Report, tc.report, got.Reason)
			}
		})
	}
}

// What a starting agent should make of whatever record it finds. The case
// that matters is the third one: a supervisor killed by a reboot or an MSI
// repair leaves a pending record nobody will ever resolve, and the old build
// is the one that came back.
func TestReconcile(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	cases := map[string]struct {
		rec     selfupdate.Record
		found   bool
		running string
		want    selfupdate.ReconcileAction
	}{
		"no record at all": {
			found: false, running: "1.0.0", want: selfupdate.ReconcileNone,
		},
		"a rollback nobody has reported yet": {
			rec:   selfupdate.Record{FromVersion: "1.0.0", ToVersion: "2.0.0", Status: selfupdate.StatusRolledBack},
			found: true, running: "1.0.0", want: selfupdate.ReconcileReport,
		},
		"a rollback that has already been reported": {
			rec: selfupdate.Record{
				FromVersion: "1.0.0", ToVersion: "2.0.0",
				Status: selfupdate.StatusRolledBack, Reported: true,
			},
			found: true, running: "1.0.0", want: selfupdate.ReconcileNone,
		},
		"a pending attempt whose supervisor is gone and whose build never came up": {
			rec: selfupdate.Record{
				FromVersion: "1.0.0", ToVersion: "2.0.0",
				Deadline: past, Status: selfupdate.StatusPending,
			},
			found: true, running: "1.0.0", want: selfupdate.ReconcileAbandon,
		},
		"a pending attempt still inside its deadline": {
			rec: selfupdate.Record{
				FromVersion: "1.0.0", ToVersion: "2.0.0",
				Deadline: future, Status: selfupdate.StatusPending,
			},
			found: true, running: "1.0.0", want: selfupdate.ReconcileNone,
		},
		"a pending attempt and this is the build it staged": {
			rec: selfupdate.Record{
				FromVersion: "1.0.0", ToVersion: "2.0.0",
				Deadline: past, Status: selfupdate.StatusPending,
			},
			found: true, running: "2.0.0", want: selfupdate.ReconcileNone,
		},
		"an attempt that already succeeded": {
			rec:   selfupdate.Record{ToVersion: "2.0.0", Status: selfupdate.StatusSucceeded},
			found: true, running: "2.0.0", want: selfupdate.ReconcileNone,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := selfupdate.Reconcile(tc.rec, tc.found, tc.running, now); got != tc.want {
				t.Errorf("action = %v, want %v", got, tc.want)
			}
		})
	}
}

// The rollback memory is per-version, not permanent: a build that failed must
// not be retried in a loop, but a later build must not be blocked by it.
func TestARolledBackVersionIsNotRetried(t *testing.T) {
	rolled := selfupdate.Record{ToVersion: "2.0.0", Status: selfupdate.StatusRolledBack}
	if d := selfupdate.Decide("1.0.0", "2.0.0", true, 1, rolled); d.Action != selfupdate.ActionNone {
		t.Error("the version that was rolled back must not be attempted again")
	}
	if d := selfupdate.Decide("1.0.0", "2.0.1", true, 1, rolled); d.Action != selfupdate.ActionUpdate {
		t.Error("a different version must still be attempted")
	}
}
