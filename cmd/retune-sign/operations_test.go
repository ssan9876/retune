package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/opsign"
	"retune/internal/release"
)

func operationsKey(t *testing.T) (dir string, pub release.PublicKey) {
	t.Helper()
	dir = t.TempDir()
	if err := run([]string{"keygen", "--out", dir, "--name", "operations"}, os.Getenv, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "operations.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err = release.DecodePublicKey(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return dir, pub
}

func TestSignScript(t *testing.T) {
	dir, pub := operationsKey(t)
	// Saved with CRLF, as Notepad would; it must verify against the LF text a
	// browser sends.
	script := filepath.Join(dir, "fix.ps1")
	if err := os.WriteFile(script, []byte("Get-Service spooler\r\nRestart-Service spooler\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detect := filepath.Join(dir, "detect.ps1")
	if err := os.WriteFile(detect, []byte("exit 0\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"sign-script", "--key", filepath.Join(dir, "operations.key"), "--detection", detect, script},
		os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	var sig opsign.Signature
	if err := json.Unmarshal(out.Bytes(), &sig); err != nil {
		t.Fatalf("output %q: %v", out.String(), err)
	}
	manifest := opsign.ScriptManifest("Get-Service spooler\nRestart-Service spooler\n", "exit 0\n")
	if err := opsign.Verify([]release.PublicKey{pub}, manifest, &sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignWipe(t *testing.T) {
	dir, pub := operationsKey(t)
	var out bytes.Buffer
	before := time.Now()
	if err := run([]string{"sign-wipe", "--key", filepath.Join(dir, "operations.key"), "--device", "0192AB",
		"--protected", "--valid-for", "2h"}, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	var order struct {
		Device    string    `json:"device"`
		Protected bool      `json:"protected"`
		Expires   time.Time `json:"expires"`
		opsign.Signature
	}
	if err := json.Unmarshal(out.Bytes(), &order); err != nil {
		t.Fatalf("output %q: %v", out.String(), err)
	}
	if !order.Protected || order.Expires.Before(before.Add(2*time.Hour-time.Second)) || order.Expires.After(time.Now().Add(2*time.Hour)) {
		t.Fatalf("order = %+v", order)
	}
	if err := opsign.VerifyWipe([]release.PublicKey{pub}, "0192ab", true, order.Expires, time.Now(), &order.Signature); err != nil {
		t.Fatalf("verify: %v", err)
	}

	for _, bad := range [][]string{
		{"sign-wipe", "--key", filepath.Join(dir, "operations.key"), "--device", "x", "--valid-for", "25h"},
		{"sign-wipe", "--key", filepath.Join(dir, "operations.key")},
		{"keygen", "--out", dir, "--name", "other"},
	} {
		if err := run(bad, os.Getenv, &bytes.Buffer{}); err == nil {
			t.Errorf("%v should fail", bad)
		}
	}
}
