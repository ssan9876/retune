package agentcfg_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/agent/agentcfg"
)

func TestSaveLoadAndClearToken(t *testing.T) {
	dir := t.TempDir()
	want := agentcfg.Config{
		ServerURL:             "https://mdm.example.com",
		EnrollToken:           "secret-token",
		ServerCertFingerprint: "sha256:abc",
	}
	if err := agentcfg.Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := agentcfg.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip: got %+v want %+v", got, want)
	}

	if err := agentcfg.ClearToken(dir); err != nil {
		t.Fatal(err)
	}
	got, err = agentcfg.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.EnrollToken != "" {
		t.Error("the spent token should be gone")
	}
	if got.ServerURL != want.ServerURL || got.ServerCertFingerprint != want.ServerCertFingerprint {
		t.Error("clearing the token must not disturb the rest of the file")
	}
	raw, err := os.ReadFile(filepath.Join(dir, agentcfg.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-token") {
		t.Error("the spent token is still on disk")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := agentcfg.Load(t.TempDir()); !errors.Is(err, agentcfg.ErrNoConfig) {
		t.Fatalf("want ErrNoConfig, got %v", err)
	}
}

func TestClearTokenIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := agentcfg.Save(dir, agentcfg.Config{ServerURL: "https://mdm.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := agentcfg.ClearToken(dir); err != nil {
		t.Fatalf("clearing an already-spent token should be a no-op: %v", err)
	}
}
