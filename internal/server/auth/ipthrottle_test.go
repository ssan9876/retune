package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// One address trying a password against account after account is stopped,
// though no single account reaches its own limit; another address is not.
func TestSignInIsThrottledPerAddress(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	svc := newService(t, &clock)
	now := func() time.Time { return clock }
	svc.Limiter = nil
	svc.Throttle = &auth.StoreThrottle{Store: svc.Store, Max: 10, Window: 15 * time.Minute, Now: now}
	svc.IPThrottle = &auth.StoreThrottle{Store: svc.Store, Max: 5, Window: 15 * time.Minute, Now: now}
	if _, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}

	for i := range 5 {
		email := fmt.Sprintf("user%d@example.com", i)
		if _, err := svc.AuthenticateFrom(ctx, "203.0.113.9", email, "Summer2026!", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("spray %d: %v", i, err)
		}
	}
	if _, err := svc.AuthenticateFrom(ctx, "203.0.113.9", "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Fatalf("the spraying address should be refused, got %v", err)
	}
	if _, err := svc.AuthenticateFrom(ctx, "198.51.100.7", "ops@example.com", "correct horse battery", ""); err != nil {
		t.Fatalf("another address: %v", err)
	}
	clock = clock.Add(16 * time.Minute)
	if _, err := svc.AuthenticateFrom(ctx, "203.0.113.9", "ops@example.com", "correct horse battery", ""); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}
