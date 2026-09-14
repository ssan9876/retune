package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/release"
)

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"keygen", "--out", dir}, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "key id: ") || !strings.Contains(out.String(), "public key: ") {
		t.Fatalf("keygen output %q", out.String())
	}
	pubB64, err := os.ReadFile(filepath.Join(dir, "release.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--out", dir}, os.Getenv, &out); err == nil {
		t.Fatal("keygen must refuse to overwrite an existing key")
	}

	bin := filepath.Join(dir, "agent.exe")
	if err := os.WriteFile(bin, []byte("pretend agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"sign", "--key", filepath.Join(dir, "release.key"), "--version", "1.4.0", bin},
		os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	sigBytes, err := os.ReadFile(bin + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.DecodeSidecar(sigBytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("pretend agent"))
	if sig.Version != "1.4.0" || sig.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sidecar %+v", sig)
	}

	out.Reset()
	if err := run([]string{"verify", "--trust", strings.TrimSpace(string(pubB64)), bin, bin + ".sig"},
		os.Getenv, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "ok: ") {
		t.Errorf("verify output %q", out.String())
	}

	// The wrong trust list refuses.
	other, _ := release.GenerateKey()
	if err := run([]string{"verify", "--trust", other.Public().Encode(), bin, bin + ".sig"},
		os.Getenv, &out); err == nil {
		t.Error("verify must fail under a trust list that lacks the signing key")
	}
	// Changed bytes refuse.
	if err := os.WriteFile(bin, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--trust", strings.TrimSpace(string(pubB64)), bin, bin + ".sig"},
		os.Getenv, &out); err == nil {
		t.Error("verify must fail when the bytes changed")
	}
}

func TestSignReadsTheKeyFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	priv, _ := release.GenerateKey()
	bin := filepath.Join(dir, "agent.exe")
	if err := os.WriteFile(bin, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "RELEASE_KEY" {
			return priv.Encode()
		}
		return ""
	}
	var out bytes.Buffer
	if err := run([]string{"sign", "--key", "env:RELEASE_KEY", "--version", "2.0.0", bin}, getenv, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin + ".sig"); err != nil {
		t.Fatal("no sidecar written")
	}
}

func TestUsageErrors(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{},
		{"nonsense"},
		{"sign", "--version", "1.0.0"},
		{"sign", "--key", "env:UNSET", "--version", "1.0.0", "x"},
		{"verify", "--trust", "", "x", "x.sig"},
	} {
		if err := run(args, func(string) string { return "" }, &out); err == nil {
			t.Errorf("args %v should fail", args)
		}
	}
}
