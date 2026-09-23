package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// A session in constant use still ends at the cap, counted from sign-in:
// otherwise someone removed at the identity provider keeps a console open for
// as long as they keep clicking.
func TestSessionsEndAtTheCapHoweverBusy(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	svc := newService(t, &clock)
	svc.MaxSessionLifetime = 24 * time.Hour
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "busy@example.com", Password: "a long enough password", Role: store.RoleAdmin, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.CreateSession(ctx, admin.ID, "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Used every hour, well inside the 12-hour idle timeout.
	for i := 0; i < 23; i++ {
		clock = clock.Add(time.Hour)
		if _, _, err := svc.ValidateSession(ctx, info.Token); err != nil {
			t.Fatalf("hour %d: %v", i+1, err)
		}
	}
	clock = clock.Add(time.Hour + time.Second)
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("a session past the cap should end, got %v", err)
	}
}
