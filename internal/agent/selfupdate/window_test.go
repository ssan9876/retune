package selfupdate_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
	"retune/internal/protocol"
)

func TestAgentUpdatesWaitForAMaintenanceWindow(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	raw, _ := json.Marshal(protocol.Window{Start: "22:00", DurationMinutes: 60})
	window := protocol.Item{Kind: protocol.ItemKindWindow, ID: "w1", Options: raw}
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: t.TempDir(), Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil), window}); err != nil {
		t.Fatal(err)
	}
	if c.fetches != 0 || c.downloads != 0 {
		t.Errorf("outside the window nothing should be fetched, got fetches=%d downloads=%d", c.fetches, c.downloads)
	}
}
