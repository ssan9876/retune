package artifacts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/server/artifacts"
)

func TestBlobs(t *testing.T) {
	b := artifacts.Blobs{Dir: filepath.Join(t.TempDir(), "pkgs")}
	body := "an installer"
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])

	sha, size, err := b.Put(strings.NewReader(body), 1<<20)
	if err != nil || sha != want || size != int64(len(body)) {
		t.Fatalf("Put = %q, %d, %v", sha, size, err)
	}
	// The same bytes again: stored once.
	if sha2, _, err := b.Put(strings.NewReader(body), 1<<20); err != nil || sha2 != sha {
		t.Fatalf("second Put = %q, %v", sha2, err)
	}
	if n, ok, err := b.Exists(sha); err != nil || !ok || n != size {
		t.Fatalf("Exists = %d, %v, %v", n, ok, err)
	}
	f, n, err := b.Open(sha)
	if err != nil || n != size {
		t.Fatalf("Open = %d, %v", n, err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != body {
		t.Fatalf("read back %q", got)
	}

	list, err := b.List()
	if err != nil || len(list) != 1 || list[0].SHA256 != sha {
		t.Fatalf("List = %+v, %v", list, err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := b.Touch(sha, old); err != nil {
		t.Fatal(err)
	}
	if list, _ := b.List(); !list[0].ModTime.Before(time.Now().Add(-47 * time.Hour)) {
		t.Fatalf("Touch didn't set the time: %v", list[0].ModTime)
	}

	if err := b.Remove(sha); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(sha); !errors.Is(err, artifacts.ErrNotFound) {
		t.Fatalf("Open after Remove = %v", err)
	}
	if err := b.Remove(sha); err != nil {
		t.Fatalf("removing twice = %v", err)
	}
}

func TestBlobsEnforceTheLimitAndRejectBadNames(t *testing.T) {
	dir := t.TempDir()
	b := artifacts.Blobs{Dir: dir}
	if _, _, err := b.Put(strings.NewReader("0123456789"), 5); !errors.Is(err, artifacts.ErrTooLarge) {
		t.Fatalf("over the limit = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
	for _, name := range []string{"", "../x", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, _, err := b.Open(name); !errors.Is(err, artifacts.ErrBadHash) {
			t.Errorf("Open(%q) = %v", name, err)
		}
		if err := b.Remove(name); !errors.Is(err, artifacts.ErrBadHash) {
			t.Errorf("Remove(%q) = %v", name, err)
		}
	}
	if err := b.RemovePart(`..\x.part`); err == nil {
		t.Error("RemovePart must refuse a path")
	}
}
