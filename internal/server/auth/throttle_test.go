package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// Two servers sharing a database share one allowance of failed sign-ins:
// an attacker whose guesses a load balancer spreads over both gets no more
// than against one.
func TestStoreThrottleIsShared(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	first := newService(t, &clock)
	throttle := func() *auth.StoreThrottle {
		return &auth.StoreThrottle{Store: first.Store, Max: 4, Window: 15 * time.Minute, Now: func() time.Time { return clock }}
	}
	first.Limiter, first.Throttle = nil, throttle()
	second := *first
	second.Throttle = throttle()
	if _, err := first.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}

	// Four wrong guesses, alternating between the servers.
	for i, svc := range []*auth.Service{first, &second, first, &second} {
		if _, err := svc.Authenticate(ctx, "ops@example.com", "wrong guess", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	// Both now refuse, even the right password.
	for name, svc := range map[string]*auth.Service{"first": first, "second": &second} {
		if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrTooManyAttempts) {
			t.Fatalf("%s after four failures: %v", name, err)
		}
	}
	// Another account isn't affected.
	if _, err := second.Authenticate(ctx, "other@example.com", "x", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("another account: %v", err)
	}
	// Once the window passes, the right password works, and clears the count.
	clock = clock.Add(16 * time.Minute)
	if _, err := second.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if n, err := first.Store.Q().CountLoginFailures(ctx, "ops@example.com", clock.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("failures after a success: %d, %v", n, err)
	}
}
