package selfupdate_test

import (
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// The record is what lets the supervisor put the service back exactly as it
// was. The arguments matter as much as the path: an MSI-installed service
// carries no --data-dir and a manually installed one does, and a repoint that
// loses that argument sends the new agent looking for its identity in the
// wrong directory.
func TestRecordRoundTripKeepsTheServiceArguments(t *testing.T) {
	dir := t.TempDir()
	want := selfupdate.Record{
		FromVersion: "1.2.3",
		FromBinPath: `C:\Program Files\Retune\retune-agent.exe`,
		FromArgs:    []string{"--data-dir", `C:\ProgramData\Retune`},
		ToVersion:   "1.3.0",
		ToBinPath:   `C:\ProgramData\Retune\bin\1.3.0\retune-agent.exe`,
		StartedAt:   time.Now().UTC().Truncate(time.Second),
		Deadline:    time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute),
		Status:      selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, want); err != nil {
		t.Fatal(err)
	}

	got, found, err := selfupdate.ReadRecord(dir)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if len(got.FromArgs) != 2 || got.FromArgs[0] != "--data-dir" {
		t.Fatalf("the service arguments must survive, got %+v", got.FromArgs)
	}
	if got.FromBinPath != want.FromBinPath || got.ToVersion != want.ToVersion {
		t.Fatalf("record = %+v", got)
	}

	if err := selfupdate.RemoveRecord(dir); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("the record should be gone")
	}
}

// No record is the ordinary state, not an error.
func TestReadRecordWithNothingThere(t *testing.T) {
	if _, found, err := selfupdate.ReadRecord(t.TempDir()); err != nil || found {
		t.Errorf("found=%v err=%v", found, err)
	}
}
