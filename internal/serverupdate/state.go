package serverupdate

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// FileStore keeps the latest update's state in a JSON file, so it outlives the
// process that wrote it and the server - restarted by the update - can read
// how it ended.
type FileStore struct {
	Path string
}

// Load reads the state, or returns nil when no update has ever run.
func (f FileStore) Load() (*State, error) {
	var b []byte
	var err error
	// Windows refuses a read for the moment a writer renames over the file.
	for try := 0; try <= 20; try++ {
		if b, err = os.ReadFile(f.Path); err == nil || errors.Is(err, fs.ErrNotExist) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes the state atomically: a reader sees the old state or the new,
// never half of one.
func (f FileStore) Save(s State) error {
	return writeJSONAtomic(f.Path, s)
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// On Windows a rename over a file someone is reading fails for a moment;
	// a reader never holds it for long.
	for try := 0; ; try++ {
		err = os.Rename(tmp.Name(), path)
		if err == nil || try == 20 {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
