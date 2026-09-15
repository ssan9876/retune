// Package artifacts stores uploaded agent builds on disk, one directory per
// version, under DATA_DIR/agents. It has no HTTP in it: an upload is just a
// stream in, and a download is just a stream out.
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
)

// ErrNotFound is returned when a version has not been uploaded.
var ErrNotFound = errors.New("artifact not found")

// ErrExists is returned by Put when the version is already stored.
var ErrExists = errors.New("that version is already stored")

// ErrBadVersion is returned by Put and Open when the version string cannot
// be used as a directory name -- a distinct sentinel from ErrExists, so a
// caller can tell a bad string from a legitimate collision and audit or
// report each one differently.
var ErrBadVersion = errors.New("invalid version")

// binaryName is the filename every version stores its build under.
const binaryName = "retune-agent.exe"

// versionPattern is deliberately narrow: a version becomes a directory name,
// so anything that could be a path separator or a "." / ".." segment must be
// refused before it ever reaches the filesystem.
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// Store keeps uploaded agent builds under Dir, one subdirectory per version.
type Store struct {
	Dir string
}

func validateVersion(version string) error {
	if version == "" || version == "." || version == ".." || !versionPattern.MatchString(version) {
		return fmt.Errorf("%w: %q", ErrBadVersion, version)
	}
	return nil
}

// Put streams r to disk, hashing as it goes, and returns the hex SHA-256 and
// the number of bytes written. It refuses to replace an existing version,
// and leaves nothing behind if the copy fails.
func (s Store) Put(version string, r io.Reader, limit int64) (sha256Hex string, size int64, err error) {
	if err := validateVersion(version); err != nil {
		return "", 0, err
	}

	dir := filepath.Join(s.Dir, version)
	final := filepath.Join(dir, binaryName)
	if _, err := os.Stat(final); err == nil {
		return "", 0, ErrExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", 0, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	// From here on, every exit path is covered by one cleanup: whatever
	// step fails, a refused upload must leave nothing behind. Using a
	// single deferred check means the next step added here can't forget it.
	tmp := final + ".part"
	defer func() {
		if err != nil {
			os.Remove(tmp)
			os.Remove(dir)
		}
	}()

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}

	hasher := sha256.New()
	// limit+1 lets an oversized upload be detected rather than silently
	// truncated: if we read past limit, the client sent too much.
	n, copyErr := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(r, limit+1))
	closeErr := f.Close()

	if copyErr == nil && n > limit {
		copyErr = fmt.Errorf("upload exceeds limit of %d bytes", limit)
	}
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		err = copyErr
		return "", 0, err
	}

	if renameErr := os.Rename(tmp, final); renameErr != nil {
		err = renameErr
		return "", 0, err
	}

	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

// Open returns the stored build for version and its size, for streaming to
// a caller. The caller must close the returned reader.
func (s Store) Open(version string) (io.ReadCloser, int64, error) {
	if err := validateVersion(version); err != nil {
		return nil, 0, err
	}

	path := filepath.Join(s.Dir, version, binaryName)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// Remove deletes a stored version. Removing one that is already gone is
// what the caller wanted anyway, so that is not an error.
func (s Store) Remove(version string) error {
	if err := validateVersion(version); err != nil {
		return err
	}
	err := os.RemoveAll(filepath.Join(s.Dir, version))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
