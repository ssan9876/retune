package apps_test

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

func TestAppsWaitForAMaintenanceWindow(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{Version: 1, PackageID: "7zip.7zip", Scope: "machine"}}
	w := &fakeWinget{}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil)), windowFrom(now.Add(2*time.Hour), 60)}); err != nil {
		t.Fatal(err)
	}
	if got := w.ran(); len(got) != 0 {
		t.Fatalf("winget ran %v outside the window", got)
	}
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil)), windowFrom(now.Add(-time.Hour), 180)}); err != nil {
		t.Fatal(err)
	}
	if got := w.ran(); len(got) < 2 || got[1] != "install" {
		t.Fatalf("inside the window it should install, got %v", got)
	}
}
