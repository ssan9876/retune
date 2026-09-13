package secrets_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"retune/internal/server/secrets"
)

func TestSealAndOpen(t *testing.T) {
	dir := t.TempDir()
	key, err := secrets.LoadOrCreateFile(dir)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("123456-234567-345678")
	context := []byte("device/volume")
	ciphertext, nonce, err := key.Seal(plaintext, context)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "123456") {
		t.Fatal("the recovery key must not be readable in the ciphertext")
	}

	got, err := key.Open(ciphertext, nonce, context)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip = %q", got)
	}
}

// The context is authenticated, so a ciphertext moved to another device or
// volume does not decrypt.
func TestContextIsAuthenticated(t *testing.T) {
	key, err := secrets.LoadOrCreateFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := key.Seal([]byte("secret"), []byte("device-a/C:"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Open(ciphertext, nonce, []byte("device-b/C:")); err == nil {
		t.Fatal("a key moved to another device should not decrypt")
	}
}

func TestAnotherKeyCannotRead(t *testing.T) {
	a, err := secrets.LoadOrCreateFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := secrets.LoadOrCreateFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := a.Seal([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Open(ciphertext, nonce, nil)
	if err == nil {
		t.Fatal("a different server key must not decrypt it")
	}
	if !strings.Contains(err.Error(), "this server's key") {
		t.Errorf("the error should explain why, got %v", err)
	}
}

func TestTheKeyIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	first, err := secrets.LoadOrCreateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := first.Seal([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Opening the same directory again must give the same key, or every
	// escrowed value would become unreadable on restart.
	second, err := secrets.LoadOrCreateFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Open(ciphertext, nonce, nil)
	if err != nil || string(got) != "secret" {
		t.Fatalf("reopening the directory should give the same key: %q %v", got, err)
	}

	info, err := os.Stat(filepath.Join(dir, secrets.FileName))
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not carry Unix permission bits, so the mode there says
	// nothing; the directory's ACL is what protects the file. The server runs
	// in a Linux container, where this is the real protection.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("the key file should not be readable by others, mode is %v", mode)
		}
	}
}

func TestFromHex(t *testing.T) {
	if _, err := secrets.FromHex(""); !errors.Is(err, secrets.ErrNoKey) {
		t.Errorf("an empty key should report ErrNoKey, got %v", err)
	}
	if _, err := secrets.FromHex("not hex"); err == nil {
		t.Error("a key that is not hex should be rejected")
	}
	if _, err := secrets.FromHex(strings.Repeat("ab", 8)); err == nil {
		t.Error("a key of the wrong length should be rejected")
	}
	if _, err := secrets.FromHex(strings.Repeat("ab", secrets.KeySize)); err != nil {
		t.Errorf("a valid key should be accepted, got %v", err)
	}
}
