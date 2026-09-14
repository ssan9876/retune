package selfupdate

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// RecordName is the file a self-update attempt is recorded under, in the
// agent's data directory.
const RecordName = "update.json"

// Record is what an in-progress or finished self-update attempt looks like on
// disk. FromBinPath and FromArgs are what let a supervisor put the old
// service back exactly as it was if the new binary never checks in: an
// MSI-installed service carries no --data-dir and a manually installed one
// does, and losing that argument on a repoint sends the restored agent
// looking for its identity in the wrong directory.
type Record struct {
	// ItemID is the server-side identifier of the build this record concerns
	// (protocol.Item.ID). A rollback is reported long after the check-in item
	// that requested it is gone -- possibly on the very next cycle -- so this
	// is the only place left to remember which endpoint to report against.
	ItemID      string    `json:"item_id"`
	FromVersion string    `json:"from_version"`
	FromBinPath string    `json:"from_bin_path"`
	FromArgs    []string  `json:"from_args"`
	ToVersion   string    `json:"to_version"`
	ToBinPath   string    `json:"to_bin_path"`
	StartedAt   time.Time `json:"started_at"`
	Deadline    time.Time `json:"deadline"`
	Status      string    `json:"status"`
	Detail      string    `json:"detail"`
}

const (
	StatusPending    = "pending"
	StatusSucceeded  = "succeeded"
	StatusRolledBack = "rolled_back"
)

// ReadRecord reads the update record from dir. A missing file is the
// ordinary state, not an error: most check-ins find no update under way.
func ReadRecord(dir string) (Record, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, RecordName))
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// WriteRecord writes the update record to dir, through a temp file and
// rename: a half-written record is worse than none, since the supervisor
// reads it to decide how to restore the service.
func WriteRecord(dir string, r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, RecordName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveRecord deletes the update record, once an attempt is resolved.
func RemoveRecord(dir string) error {
	if err := os.Remove(filepath.Join(dir, RecordName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
