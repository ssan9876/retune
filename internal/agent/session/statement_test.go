package session

import (
	"os"
	"path/filepath"
	"testing"
)

// The statement is replaced whole, leaving nothing half-written beside it.
func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compliance.jwt")
	for _, content := range []string{"first\n", "second, longer\n", "3\n"} {
		if err := writeAtomic(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read %q, %v; want %q", got, err, content)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files left, want 1", len(entries))
	}
}
