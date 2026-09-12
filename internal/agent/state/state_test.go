package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	if hash, err := s.InventoryHash(); err != nil || hash != "" {
		t.Fatalf("initial inventory hash = %q, %v", hash, err)
	}
	if pending, err := s.PendingResults(); err != nil || len(pending) != 0 {
		t.Fatalf("initial pending = %+v, %v", pending, err)
	}

	// Results queue, ordered by command ID.
	for _, id := range []string{"b", "a"} {
		if err := s.QueueResult(QueuedResult{
			CommandID: id,
			Result:    protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "out-" + id, StartedAt: now, FinishedAt: now},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.PendingResults()
	if err != nil || len(pending) != 2 || pending[0].CommandID != "a" || pending[0].Result.Stdout != "out-a" {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if err := s.DeleteResult("a"); err != nil {
		t.Fatal(err)
	}
	if pending, _ = s.PendingResults(); len(pending) != 1 || pending[0].CommandID != "b" {
		t.Fatalf("pending after delete = %+v", pending)
	}

	// Command ledger.
	first, err := s.MarkStarted("cmd-1", now)
	if err != nil || !first {
		t.Fatalf("MarkStarted = %v, %v", first, err)
	}
	if first, _ = s.MarkStarted("cmd-1", now); first {
		t.Fatal("a second MarkStarted must report the command was already seen")
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerStarted {
		t.Fatalf("ledger state = %q", got)
	}
	if err := s.MarkCompleted("cmd-1", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatalf("ledger state = %q", got)
	}
	if got, err := s.LedgerState("unknown"); err != nil || got != "" {
		t.Fatalf("unknown ledger state = %q, %v", got, err)
	}

	if err := s.SetInventoryHash("h1"); err != nil {
		t.Fatal(err)
	}

	// State survives a reopen.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash, _ := s.InventoryHash(); hash != "h1" {
		t.Fatalf("hash after reopen = %q", hash)
	}
	if pending, _ = s.PendingResults(); len(pending) != 1 {
		t.Fatalf("pending after reopen = %+v", pending)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatalf("ledger after reopen = %q", got)
	}

	// Pruning drops old ledger entries only.
	if _, err := s.MarkStarted("old", now.Add(-60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneLedger(now.Add(-30 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneLedger = %d, %v", n, err)
	}
	if got, _ := s.LedgerState("old"); got != "" {
		t.Fatalf("pruned entry still present: %q", got)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatal("pruning must keep recent entries")
	}

	if err := s.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file still exists: %v", err)
	}
}
