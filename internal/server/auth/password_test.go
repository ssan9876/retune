package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash = %q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery") {
		t.Fatal("the right password must verify")
	}
	if VerifyPassword(hash, "wrong horse battery") {
		t.Fatal("the wrong password must not verify")
	}

	other, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Fatal("each hash must use a fresh salt")
	}

	for _, bad := range []string{"", "$argon2id$broken", "$argon2id$v=19$m=65536,t=3,p=4$notbase64$x"} {
		if VerifyPassword(bad, "correct horse battery") {
			t.Fatalf("malformed hash %q must not verify", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short password err = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 1025)); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("overlong password err = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Fatalf("minimum length must be accepted: %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) < MinPasswordLength || a == b {
		t.Fatalf("generated passwords = %q, %q", a, b)
	}
	if _, err := HashPassword(a); err != nil {
		t.Fatalf("a generated password must satisfy the policy: %v", err)
	}
}
