//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Every path that puts something sensitive in the data directory calls this,
// and most of them call it on a directory that has already been secured, so
// it has to be safe to repeat. It also has to be safe to call before the
// directory exists: enroll and install both run before anything has created
// it.
func TestSecureDataDirIsIdempotentAndCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Retune")

	if err := secureDataDir(dir); err != nil {
		t.Fatalf("securing a directory that does not exist yet: %v", err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("the directory should exist afterwards: %v", err)
	}
	if err := secureDataDir(dir); err != nil {
		t.Fatalf("securing an already secured directory: %v", err)
	}
}
