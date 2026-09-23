package selfupdate_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// A service with no arguments reads back as no arguments, whether the caller
// had a nil slice or an empty one.
func TestRecordWithNoArgumentsRoundTripsAsEmpty(t *testing.T) {
	for name, args := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := selfupdate.WriteRecord(dir, selfupdate.Record{FromArgs: args}); err != nil {
				t.Fatal(err)
			}
			got, _, err := selfupdate.ReadRecord(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.FromArgs == nil || len(got.FromArgs) != 0 {
				t.Errorf("FromArgs = %#v, want an empty slice", got.FromArgs)
			}
		})
	}
}

// A write that cannot be put in place leaves nothing behind: a stray temp
// file would sit in the data directory until the next successful write.
func TestWriteRecordCleansUpAFailedRename(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory where the record belongs makes the rename fail
	// on every platform.
	if err := os.MkdirAll(filepath.Join(dir, selfupdate.RecordName, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := selfupdate.WriteRecord(dir, selfupdate.Record{Status: selfupdate.StatusPending}); err == nil {
		t.Fatal("the write should fail")
	}
	if _, err := os.Stat(filepath.Join(dir, selfupdate.RecordName+".tmp")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the temp file should be gone, stat err = %v", err)
	}
}

// No record is the ordinary state, not an error.
func TestReadRecordWithNothingThere(t *testing.T) {
	if _, found, err := selfupdate.ReadRecord(t.TempDir()); err != nil || found {
		t.Errorf("found=%v err=%v", found, err)
	}
}
