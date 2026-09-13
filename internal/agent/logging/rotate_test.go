package logging_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/agent/logging"
)

func TestRotateKeepsBoundedHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	w, err := logging.NewRotatingFile(path, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := strings.Repeat("x", 40) + "\n"
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 3 {
		t.Fatalf("kept %d files, want at most 3: %v", len(entries), entries)
	}
	for _, e := range entries {
		st, err := os.Stat(e)
		if err != nil {
			t.Fatal(err)
		}
		// One record may take a file slightly past the limit; what matters is
		// that it is bounded rather than growing without end.
		if st.Size() > 200 {
			t.Errorf("%s is %d bytes, rotation did not bound it", e, st.Size())
		}
	}
}

func TestRotateKeepsTheNewestRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	w, err := logging.NewRotatingFile(path, 60, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	for _, s := range []string{"first\n", strings.Repeat("a", 55) + "\n", "newest\n"} {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(live), "newest") {
		t.Fatalf("the live file should hold the newest record, got %q", live)
	}
}

func TestLoggerWritesToTheDataDir(t *testing.T) {
	dir := t.TempDir()
	log, closeLog, err := logging.New(logging.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "key", "value")
	if err := closeLog(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "logs", "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hello") || !strings.Contains(string(body), "key=value") {
		t.Fatalf("log file = %q", body)
	}
}
