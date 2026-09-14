package apps_test

import (
	"testing"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func opts(mutate func(*protocol.AppOptions)) protocol.AppOptions {
	o := protocol.DefaultAppOptions()
	if mutate != nil {
		mutate(&o)
	}
	return o
}

func uninstall() protocol.AppOptions {
	return opts(func(o *protocol.AppOptions) { o.Intent = protocol.IntentUninstall })
}

func TestDecide(t *testing.T) {
	// Every state that represents an app already acted on carries the intent
	// it was acted on under. A zero Intent means "never acted on", which is a
	// fresh instruction however the rest of the state reads.
	const install, remove = protocol.IntentInstall, protocol.IntentUninstall

	cases := map[string]struct {
		version int
		opts    protocol.AppOptions
		state   state.AppState
		want    apps.Action
	}{
		"never seen before": {
			version: 1, opts: opts(nil), state: state.AppState{},
			want: apps.ActionDetect,
		},
		"a new version is a fresh instruction": {
			version: 2, opts: opts(nil),
			state: state.AppState{Version: 1, Intent: install, Installed: true, LastSeenAt: now},
			want:  apps.ActionDetect,
		},
		"a changed intent is re-checked before acting on it": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Intent: install, Installed: true, LastSeenAt: now},
			want:  apps.ActionDetect,
		},
		"installed and checked recently: nothing to do": {
			version: 1, opts: opts(nil),
			state: state.AppState{
				Version: 1, Intent: install, Installed: true, LastSeenAt: now.Add(-10 * time.Minute),
			},
			want: apps.ActionNone,
		},
		"installed but not checked for an hour": {
			version: 1, opts: opts(nil),
			state: state.AppState{
				Version: 1, Intent: install, Installed: true, LastSeenAt: now.Add(-90 * time.Minute),
			},
			want: apps.ActionDetect,
		},
		"detected missing, so put it back": {
			version: 1, opts: opts(nil),
			state: state.AppState{Version: 1, Intent: install, Installed: false, LastSeenAt: now},
			want:  apps.ActionInstall,
		},
		"uninstall intent with it still present": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Intent: remove, Installed: true, LastSeenAt: now},
			want:  apps.ActionUninstall,
		},
		"uninstall intent with it already gone": {
			version: 1, opts: uninstall(),
			state: state.AppState{Version: 1, Intent: remove, Installed: false, LastSeenAt: now},
			want:  apps.ActionNone,
		},
		"it has failed too often to keep trying": {
			version: 1, opts: opts(nil),
			state: state.AppState{
				Version: 1, Intent: install, Installed: false, LastSeenAt: now, LastActedAt: now,
				LastStatus: protocol.ResultFailed, Failures: 3,
			},
			want: apps.ActionNone,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := apps.Decide(tc.version, tc.opts, tc.state, now)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v (reason %q)", got.Action, tc.want, got.Reason)
			}
			if got.Action == apps.ActionNone && got.Reason == "" {
				t.Error("a decision to do nothing should say why, for the agent's log")
			}
		})
	}
}
