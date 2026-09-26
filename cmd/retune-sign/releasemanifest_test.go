package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/release"
)

// The release workflow's path: write release.json from the files in dist,
// sign it, and verify it, as a server will.
func TestReleaseManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"keygen", "--out", dir}, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "release.pub"))
	if err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"retune-agent.exe":          "windows agent",
		"retune-agent.exe.sig":      "{}",
		"retune-agent-darwin-arm64": "mac agent",
		"retune-server-linux-amd64": "server",
		"SHA256SUMS":                "sums",
	} {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	notes := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(notes, []byte("## Changes\n- one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dist, "release.json")
	files, _ := filepath.Glob(filepath.Join(dist, "*"))
	args := append([]string{"release-manifest", "--version", "1.4.0", "--notes", notes,
		"--image", "ghcr.io/x/retune-server", "--image-digest", "sha256:" + strings.Repeat("a", 64),
		"--out", manifest}, files...)
	if err := run(args, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign-release", "--key", filepath.Join(dir, "release.key"), manifest}, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	trust := strings.TrimSpace(string(pub))
	if err := run([]string{"verify-release", "--trust", trust, manifest, manifest + ".sig"}, os.Getenv, &out); err != nil {
		t.Fatalf("verify-release: %v", err)
	}

	raw, _ := os.ReadFile(manifest)
	var m release.ReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Notes != "## Changes\n- one\n" {
		t.Errorf("notes = %q", m.Notes)
	}
	if a, ok := m.Find(release.AssetAgent, "windows", "amd64"); !ok || a.Size != int64(len("windows agent")) {
		t.Errorf("windows agent missing or wrong: %+v", a)
	}
	if _, ok := m.Named("release.json"); ok {
		t.Error("the manifest must not list itself")
	}
	if img, ok := m.ServerImage(); !ok || img.Image != "ghcr.io/x/retune-server" {
		t.Errorf("server image missing: %+v", m.Assets)
	}

	// An edited manifest no longer verifies.
	if err := os.WriteFile(manifest, bytes.Replace(raw, []byte("1.4.0"), []byte("1.4.1"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-release", "--trust", trust, manifest, manifest + ".sig"}, os.Getenv, &out); err == nil {
		t.Fatal("an edited manifest must not verify")
	}
}
