package selfupdate_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
	"retune/internal/protocol"
)

// The right version built for another machine passes every signature check,
// so the header is what catches it: the build is refused before the service
// is touched, the refusal is reported with the reason, and it is remembered
// so the same bytes are not downloaded on every check-in.
func TestSyncRefusesABuildForAnotherPlatform(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("a Windows build, say")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: &fakeControl{binPath: "/usr/local/bin/retune-agent"},
		Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn:           func(string) error { t.Fatal("a wrong build must not be handed off"); return nil },
		CheckExecutable: func(string) error { return selfupdate.ErrWrongPlatform },
	}

	for range 2 {
		if err := s.Sync(context.Background(), []protocol.Item{agentItem("v2", nil)}); err != nil {
			t.Fatal(err)
		}
	}
	if c.downloads != 1 {
		t.Errorf("the refused build should be downloaded once, not %d times", c.downloads)
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed ||
		!strings.Contains(c.reports[0].Detail, "cannot run here") {
		t.Fatalf("the refusal should be reported once with its reason, got %+v", c.reports)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the wrong build should not be left staged: %v", err)
	}
	rec, _, _ := selfupdate.ReadRecord(dir)
	if rec.Status != selfupdate.StatusRefused {
		t.Errorf("want a refused record, got %+v", rec)
	}
}

// A staged build is executable: launchd and systemd cannot start one that is
// not, and the download creates the file as plain data.
func TestSyncStagesAnExecutable(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	var checked string
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: &fakeControl{binPath: "/usr/local/bin/retune-agent"},
		Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn:           func(string) error { return nil },
		CheckExecutable: func(p string) error { checked = p; return nil },
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v2", nil)}); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "bin", "2.0.0", selfupdate.BinName)
	if checked != staged {
		t.Errorf("the staged build should be checked, checked %q", checked)
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o100 == 0 && os.PathSeparator == '/' {
		t.Errorf("the staged build should be executable, mode %v", mode)
	}
}

// Where self-update cannot work -- an agent run by hand, not as a service --
// the refusal names that reason rather than a generic one.
func TestSyncReportsWhySelfUpdateIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn:       func(string) error { t.Fatal("nothing should be handed off"); return nil },
		Unavailable: selfupdate.ErrNotInstalled,
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v2", nil)}); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 || c.reports[0].Detail != selfupdate.ErrNotInstalled.Error() {
		t.Fatalf("want the real reason reported, got %+v", c.reports)
	}
}
