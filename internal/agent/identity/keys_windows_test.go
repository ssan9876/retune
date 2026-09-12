//go:build windows

package identity

import (
	"bytes"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	plain := []byte("secret key material")
	sealed, err := DPAPIKeys{}.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed data contains plaintext")
	}
	got, err := DPAPIKeys{}.Unprotect(sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Unprotect = %q, %v", got, err)
	}
}
