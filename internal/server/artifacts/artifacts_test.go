package artifacts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"retune/internal/server/artifacts"
)

func TestPutHashesWhatItWrote(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	const body = "a pretend agent binary"

	sum, size, err := s.Put("1.2.3", strings.NewReader(body), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(body))
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", sum, hex.EncodeToString(want[:]))
	}
	if size != int64(len(body)) {
		t.Errorf("size = %d, want %d", size, len(body))
	}

	r, got, err := s.Open("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got != int64(len(body)) {
		t.Errorf("Open reported %d bytes, want %d", got, len(body))
	}
	read, _ := io.ReadAll(r)
	if string(read) != body {
		t.Errorf("read back %q", read)
	}
}

// A build is immutable once uploaded. Replacing one silently would mean two
// devices could install different bytes for the same version.
func TestPutRefusesToReplace(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	if _, _, err := s.Put("1.0.0", strings.NewReader("first"), 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put("1.0.0", strings.NewReader("second"), 1<<20); !errors.Is(err, artifacts.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	r, _, err := s.Open("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if read, _ := io.ReadAll(r); string(read) != "first" {
		t.Errorf("the original bytes should survive, got %q", read)
	}
}

// An upload larger than the limit is refused, and leaves nothing behind --
// otherwise a hostile or broken client could fill the disk a partial file at
// a time.
func TestPutEnforcesTheLimitAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	s := artifacts.Store{Dir: dir}

	_, _, err := s.Put("2.0.0", strings.NewReader(strings.Repeat("x", 100)), 10)
	if err == nil {
		t.Fatal("an oversized upload should be refused")
	}
	if _, _, err := s.Open("2.0.0"); !errors.Is(err, artifacts.ErrNotFound) {
		t.Errorf("a refused upload must leave nothing readable, got %v", err)
	}
}

func TestOpenAndRemoveMissing(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	if _, _, err := s.Open("nope"); !errors.Is(err, artifacts.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	// Removing something already gone is what the caller wanted anyway.
	if err := s.Remove("nope"); err != nil {
		t.Errorf("removing a missing artifact should be fine, got %v", err)
	}
}

// A version string arrives from an administrator and becomes a path segment,
// so it must not be able to escape the directory. ErrBadVersion is a distinct
// sentinel from ErrExists, so a caller can map each to its own audited
// rejection rather than treating a bad string like a legitimate collision.
func TestPutRejectsAPathTraversingVersion(t *testing.T) {
	dir := t.TempDir()
	s := artifacts.Store{Dir: dir}
	for _, bad := range []string{"../evil", "a/b", `a\b`, "", "."} {
		if _, _, err := s.Put(bad, strings.NewReader("x"), 1<<20); !errors.Is(err, artifacts.ErrBadVersion) {
			t.Errorf("version %q: want ErrBadVersion, got %v", bad, err)
		}
		// Rejection must happen before any filesystem call, not just before
		// the return -- nothing should ever be created under Dir.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("version %q should create nothing under Dir, found %v", bad, entries)
		}
	}
}
