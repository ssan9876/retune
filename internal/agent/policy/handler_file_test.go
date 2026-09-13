package policy_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

func fileSetting(path, content string) protocol.Setting {
	return protocol.Setting{
		Kind: protocol.KindFile, Path: path,
		ContentBase64: base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

func TestFileHandlerCreatesAndCorrects(t *testing.T) {
	ctx := context.Background()
	h := policy.FileHandler{}
	path := filepath.Join(t.TempDir(), "nested", "motd.txt")
	s := fileSetting(path, "hello")

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("a missing file is not compliant: ok=%v err=%v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("after Set it should be compliant: ok=%v err=%v", ok, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hello" {
		t.Fatalf("contents = %q err %v", got, err)
	}

	// Drift is corrected.
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.Test(ctx, s); ok {
		t.Fatal("changed contents should not be compliant")
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.Test(ctx, s); !ok {
		t.Fatal("it should be compliant again")
	}
}

func TestFileHandlerAbsent(t *testing.T) {
	ctx := context.Background()
	h := policy.FileHandler{}
	path := filepath.Join(t.TempDir(), "unwanted.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := protocol.Setting{Kind: protocol.KindFile, Path: path, Ensure: protocol.EnsureAbsent}

	if ok, _ := h.Test(ctx, s); ok {
		t.Fatal("a file that exists is not compliant with ensure: absent")
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("after removal it should be compliant: ok=%v err=%v", ok, err)
	}
	// Removing something already gone is fine.
	if err := h.Set(ctx, s); err != nil {
		t.Fatalf("removing a missing file should not fail: %v", err)
	}
}

func TestFileHandlerRevert(t *testing.T) {
	ctx := context.Background()
	h := policy.FileHandler{}
	dir := t.TempDir()

	t.Run("restores previous contents", func(t *testing.T) {
		path := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		s := fileSetting(path, "managed")

		prior, err := h.Get(ctx, s)
		if err != nil || !prior.Exists {
			t.Fatalf("prior = %+v err %v", prior, err)
		}
		if err := h.Set(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := h.Revert(ctx, s, prior); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "original" {
			t.Fatalf("after revert = %q err %v", got, err)
		}
	})

	t.Run("removes a file it created", func(t *testing.T) {
		path := filepath.Join(dir, "created.txt")
		s := fileSetting(path, "managed")

		prior, err := h.Get(ctx, s)
		if err != nil || prior.Exists {
			t.Fatalf("a missing file should report Exists false, got %+v", prior)
		}
		if err := h.Set(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := h.Revert(ctx, s, prior); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("a file this agent created should be removed on revert")
		}
	})
}
