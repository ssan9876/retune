package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"retune/internal/protocol"
)

// FileHandler manages the contents of a file.
type FileHandler struct{}

func (FileHandler) Kind() string { return protocol.KindFile }

func filePath(s protocol.Setting) string {
	return filepath.FromSlash(protocol.NormalizePath(s.Path))
}

// fileState is what was there before, kept so the file can be put back.
type fileState struct {
	// Content is the file's previous contents. A file over the cap is not
	// recorded, and Exists on the State stays false, because restoring
	// something this agent never held would be a lie.
	Content []byte `json:"content,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
}

func (FileHandler) Get(_ context.Context, s protocol.Setting) (State, error) {
	if err := checkNoLinks(filePath(s)); err != nil {
		return State{}, err
	}
	info, err := os.Stat(filePath(s))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	if info.Size() > protocol.MaxFileBytes {
		// Too big to hold on to; say it exists but record no contents, so a
		// revert does not claim to restore something it never had.
		return State{Exists: true}, nil
	}
	content, err := os.ReadFile(filePath(s))
	if err != nil {
		return State{}, err
	}
	raw, err := json.Marshal(fileState{Content: content, Mode: uint32(info.Mode().Perm())})
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (FileHandler) Test(_ context.Context, s protocol.Setting) (bool, error) {
	path := filePath(s)
	if err := checkNoLinks(path); err != nil {
		return false, err
	}
	if s.Ensure == protocol.EnsureAbsent {
		_, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, ignoreNotExist(err)
	}

	want, err := s.Content()
	if err != nil {
		return false, err
	}
	got, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Compare by hash rather than bytes: the file may be large, and this is
	// what the profile's own hash means anyway.
	return sha256.Sum256(got) == sha256.Sum256(want), nil
}

func (FileHandler) Set(_ context.Context, s protocol.Setting) error {
	path := filePath(s)
	if err := checkNoLinks(path); err != nil {
		return err
	}
	if s.Ensure == protocol.EnsureAbsent {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	content, err := s.Content()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Again, now the folders exist: a link made while they were being
	// created would otherwise be written through.
	if err := checkNoLinks(path); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

// Revert restores the file as it was, or removes one this agent created.
func (FileHandler) Revert(_ context.Context, s protocol.Setting, prior State) error {
	path := filePath(s)
	if err := checkNoLinks(path); err != nil {
		return err
	}
	if !prior.Exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if len(prior.Data) == 0 {
		// It existed but its contents were never recorded, so leave it alone
		// rather than replacing it with nothing.
		return nil
	}
	var was fileState
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	mode := fs.FileMode(was.Mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, was.Content, mode)
}

// Sum is the hash of a file setting's contents, used in tests and diagnostics.
func Sum(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func ignoreNotExist(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
