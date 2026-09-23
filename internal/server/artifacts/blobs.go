package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Blobs keeps uploaded files named by their SHA-256, so the same installer
// uploaded twice is stored once and a file can't be swapped under a name.
type Blobs struct {
	Dir string
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrBadHash is returned for a name that isn't a lowercase SHA-256.
var ErrBadHash = errors.New("not a SHA-256 hash")

// ErrTooLarge is returned by Put for a body over the limit.
var ErrTooLarge = errors.New("the upload is larger than allowed")

func (b Blobs) path(sha string) (string, error) {
	if !shaPattern.MatchString(sha) {
		return "", ErrBadHash
	}
	return filepath.Join(b.Dir, sha), nil
}

// Put stores r, at most limit bytes, and returns its hash and size. An
// existing copy is kept and the new one discarded.
func (b Blobs) Put(r io.Reader, limit int64) (string, int64, error) {
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(b.Dir, "upload-*.part")
	if err != nil {
		return "", 0, err
	}
	part := f.Name()
	defer os.Remove(part) // a no-op once renamed

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	if n > limit {
		return "", 0, fmt.Errorf("%w (%d bytes)", ErrTooLarge, limit)
	}
	sha := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(b.Dir, sha)
	if _, err := os.Stat(final); err == nil {
		return sha, n, nil
	}
	if err := os.Rename(part, final); err != nil {
		return "", 0, err
	}
	return sha, n, nil
}

// Exists reports whether a file with this hash is stored, and its size.
func (b Blobs) Exists(sha string) (int64, bool, error) {
	path, err := b.path(sha)
	if err != nil {
		return 0, false, err
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return fi.Size(), true, nil
}

// Open returns a stored file and its size.
func (b Blobs) Open(sha string) (io.ReadCloser, int64, error) {
	path, err := b.path(sha)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// Touch marks a stored file as just used, for whoever clears out old ones.
func (b Blobs) Touch(sha string, at time.Time) error {
	path, err := b.path(sha)
	if err != nil {
		return err
	}
	return os.Chtimes(path, at, at)
}

// Remove deletes a stored file; one already gone is not an error.
func (b Blobs) Remove(sha string) error {
	path, err := b.path(sha)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// BlobInfo is one stored file.
type BlobInfo struct {
	SHA256  string
	ModTime time.Time
}

// List returns every stored file, and every abandoned partial upload's name
// with a ".part" suffix, so a caller can clear out both.
func (b Blobs) List() ([]BlobInfo, error) {
	entries, err := os.ReadDir(b.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []BlobInfo
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(shaPattern.MatchString(name) || strings.HasSuffix(name, ".part")) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BlobInfo{SHA256: name, ModTime: fi.ModTime()})
	}
	return out, nil
}

// RemovePart deletes an abandoned partial upload named by List.
func (b Blobs) RemovePart(name string) error {
	if !strings.HasSuffix(name, ".part") || strings.ContainsAny(name, `/\`) {
		return ErrBadHash
	}
	if err := os.Remove(filepath.Join(b.Dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
