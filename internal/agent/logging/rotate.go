package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile is an io.Writer that keeps a bounded amount of log history.
// A service runs for months, so the log has to have a ceiling; this is a few
// dozen lines of code rather than a dependency.
type RotatingFile struct {
	path     string
	maxBytes int64
	keep     int

	mu   sync.Mutex
	fh   *os.File
	size int64
}

// NewRotatingFile opens path, rotating it once a write would take it past
// maxBytes and keeping at most keep files in total.
func NewRotatingFile(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if maxBytes <= 0 {
		return nil, errors.New("logging: maxBytes must be positive")
	}
	if keep < 1 {
		return nil, errors.New("logging: keep must be at least 1")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	fh, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := fh.Stat()
	if err != nil {
		fh.Close()
		return err
	}
	r.fh, r.size = fh, info.Size()
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Rotate before writing, so one record is never split across two files.
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.fh.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate shifts agent.log to agent.log.1, agent.log.1 to agent.log.2, and so
// on, dropping whatever falls off the end.
func (r *RotatingFile) rotate() error {
	if err := r.fh.Close(); err != nil {
		return err
	}
	if r.keep == 1 {
		// No history at all: the live file is the only one kept.
		if err := os.Remove(r.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return r.open()
	}
	// keep counts the live file, so the numbered files run .1 to .keep-1 and
	// the oldest falls off the end.
	if err := os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep-1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for i := r.keep - 2; i >= 1; i-- {
		newer := fmt.Sprintf("%s.%d", r.path, i)
		older := fmt.Sprintf("%s.%d", r.path, i+1)
		if err := os.Rename(newer, older); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return r.open()
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fh == nil {
		return nil
	}
	err := r.fh.Close()
	r.fh = nil
	return err
}
