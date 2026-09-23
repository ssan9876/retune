package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

var (
	// ErrConflict is returned when a command can't take an upload in its
	// state, or already has one.
	ErrConflict = errors.New("conflict")
	// ErrTooLarge is returned for an upload over the limit.
	ErrTooLarge = errors.New("the upload is too large")
)

// ArtifactRetention is how long a command's file is kept.
const ArtifactRetention = 30 * 24 * time.Hour

func (s *Service) artifactPath(id uuid.UUID) string {
	return filepath.Join(s.ArtifactDir, id.String()+".zip")
}

// UploadArtifact stores the file a running collect_logs command produced.
// Only the device the command belongs to may upload it, and only once.
func (s *Service) UploadArtifact(ctx context.Context, deviceID, commandID uuid.UUID, body io.Reader) error {
	if s.ArtifactDir == "" {
		return fmt.Errorf("%w: this server has nowhere to keep command files", ErrConflict)
	}
	c, err := s.Store.Q().GetCommand(ctx, store.DefaultTenantID, commandID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if c.Type != protocol.CommandCollectLogs {
		return fmt.Errorf("%w: a %s command has no file to upload", ErrConflict, c.Type)
	}
	if c.Status != store.CommandRunning {
		return fmt.Errorf("%w: the command is %s, not running", ErrConflict, c.Status)
	}
	if err := os.MkdirAll(s.ArtifactDir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.ArtifactDir, commandID.String()+"-*.part")
	if err != nil {
		return err
	}
	part := f.Name()
	defer os.Remove(part) // a no-op once renamed
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, protocol.MaxLogArchiveBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > protocol.MaxLogArchiveBytes {
		return ErrTooLarge
	}
	// The row first: its primary key is what makes a second upload lose,
	// before it can touch the first one's file.
	err = s.Store.Q().InsertCommandArtifact(ctx, store.CommandArtifact{
		CommandID: commandID, SizeBytes: n, SHA256: hex.EncodeToString(h.Sum(nil)), CreatedAt: s.Now(),
	})
	if errors.Is(err, store.ErrDuplicate) {
		return fmt.Errorf("%w: this command already has a file", ErrConflict)
	}
	if err != nil {
		return err
	}
	if err := os.Rename(part, s.artifactPath(commandID)); err != nil {
		// The record must not claim a file that isn't there.
		if derr := s.Store.Q().DeleteCommandArtifact(ctx, commandID); derr != nil {
			return errors.Join(err, derr)
		}
		return err
	}
	return nil
}

// OpenArtifact returns a command's file, with its record and the command.
func (s *Service) OpenArtifact(ctx context.Context, commandID uuid.UUID) (io.ReadCloser, store.CommandArtifact, error) {
	a, err := s.Store.Q().GetCommandArtifact(ctx, commandID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, a, ErrNotFound
	}
	if err != nil {
		return nil, a, err
	}
	f, err := os.Open(s.artifactPath(commandID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, a, fmt.Errorf("%w: the file is missing from the data directory", ErrNotFound)
	}
	return f, a, err
}

// PruneArtifacts removes command files past ArtifactRetention, and any file
// with no record: an upload that died, or one whose command was deleted by
// retention.
func (s *Service) PruneArtifacts(ctx context.Context, now time.Time) (int64, error) {
	if s.ArtifactDir == "" {
		return 0, nil
	}
	var removed int64
	for {
		ids, err := s.Store.Q().DeleteCommandArtifactsBefore(ctx, now.Add(-ArtifactRetention), 500)
		if err != nil {
			return removed, err
		}
		for _, id := range ids {
			if err := os.Remove(s.artifactPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return removed, err
			}
			removed++
		}
		if len(ids) < 500 {
			break
		}
	}
	entries, err := os.ReadDir(s.ArtifactDir)
	if errors.Is(err, fs.ErrNotExist) {
		return removed, nil
	}
	if err != nil {
		return removed, err
	}
	for _, e := range entries {
		info, err := e.Info()
		// An hour is far longer than any upload takes.
		if err != nil || e.IsDir() || now.Sub(info.ModTime()) < time.Hour {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".part") {
			id, err := uuid.Parse(strings.TrimSuffix(name, ".zip"))
			if err != nil || !strings.HasSuffix(name, ".zip") {
				continue // not ours
			}
			if ok, err := s.Store.Q().CommandArtifactExists(ctx, id); err != nil {
				return removed, err
			} else if ok {
				continue
			}
		}
		if err := os.Remove(filepath.Join(s.ArtifactDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
