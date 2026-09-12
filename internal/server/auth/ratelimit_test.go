package auth

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	l := NewLimiter(3, 15*time.Minute, func() time.Time { return clock })

	if !l.Allowed("a@example.com") {
		t.Fatal("a fresh key must be allowed")
	}
	for range 3 {
		l.Fail("a@example.com")
	}
	if l.Allowed("a@example.com") {
		t.Fatal("the key must be blocked after reaching the limit")
	}
	if !l.Allowed("b@example.com") {
		t.Fatal("other keys must be unaffected")
	}

	// A success clears the count.
	l.Reset("a@example.com")
	if !l.Allowed("a@example.com") {
		t.Fatal("Reset must clear failures")
	}

	for range 3 {
		l.Fail("a@example.com")
	}
	clock = now.Add(16 * time.Minute)
	if !l.Allowed("a@example.com") {
		t.Fatal("failures must expire with the window")
	}
}
