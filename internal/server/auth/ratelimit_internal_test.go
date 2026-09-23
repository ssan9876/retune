package auth

import (
	"testing"
	"time"
)

// Asking about a key, or holding failures that have all expired, must not
// make the limiter remember it: the keys are whatever someone typed.
func TestLimiterForgetsKeysWithNothingRecent(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	l := NewLimiter(3, time.Minute, func() time.Time { return now })
	for i := 0; i < 1000; i++ {
		l.Allowed(string(rune('a'+i%26)) + "@example.com" + string(rune(i)))
	}
	if n := l.size(); n != 0 {
		t.Fatalf("asking should remember nothing, remembered %d", n)
	}
	l.Fail("x@example.com")
	now = now.Add(2 * time.Minute)
	if !l.Allowed("x@example.com") || l.size() != 0 {
		t.Fatalf("expired failures should be forgotten, size %d", l.size())
	}
}

func TestLimiterIsBounded(t *testing.T) {
	now := time.Now()
	l := NewLimiter(3, time.Hour, func() time.Time { return now })
	for i := 0; i < maxLimiterKeys+500; i++ {
		l.Fail(time.Duration(i).String())
	}
	if n := l.size(); n > maxLimiterKeys {
		t.Fatalf("the limiter holds %d keys, more than %d", n, maxLimiterKeys)
	}
}
