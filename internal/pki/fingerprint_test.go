package pki

import "testing"

func TestFingerprint(t *testing.T) {
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Fingerprint(nil); got != want {
		t.Fatalf("Fingerprint(nil) = %s", got)
	}
}
