package scripts_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"retune/internal/protocol"
)

func windowFrom(start time.Time, minutes int) protocol.Item {
	raw, err := json.Marshal(protocol.Window{Start: start.Format("15:04"), DurationMinutes: minutes})
	if err != nil {
		panic(err)
	}
	return protocol.Item{Kind: protocol.ItemKindWindow, ID: "w1", Options: raw}
}

// A device with a maintenance window runs deployments only inside it.
func TestScriptsWaitForAMaintenanceWindow(t *testing.T) {
	client := &fakeClient{version: protocol.ScriptVersionResponse{Version: 1, Body: "install"}}
	runner := &fakeRunner{exits: map[string]int{"install": 0}}
	s, _ := newScheduler(t, client, runner)

	later := windowFrom(now.Add(2*time.Hour), 60)
	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil)), later}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 0 {
		t.Fatalf("ran %v outside the window", got)
	}
	open := windowFrom(now.Add(-time.Hour), 180)
	if err := s.Sync(context.Background(), []protocol.Item{item("s1", 1, opts(nil)), later, open}); err != nil {
		t.Fatal(err)
	}
	if got := runner.ran(); len(got) != 1 {
		t.Fatalf("ran %v inside the window, want the script once", got)
	}
}
