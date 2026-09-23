package app_test

import (
	"context"
	"errors"
	"testing"

	"retune/internal/config"
	"retune/internal/server/store"
)

// A running server holds the lock that keeps the secret key from being
// rotated underneath it, and lets go when it closes.
func TestServerHoldsTheRunningLock(t *testing.T) {
	var url string
	a, _ := newTestAppWith(t, func(c *config.Server) { url = c.DatabaseURL })
	ctx := context.Background()
	other, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	noop := func(*store.Queries) error { return nil }
	if err := other.WithServersStopped(ctx, noop); !errors.Is(err, store.ErrServerRunning) {
		t.Fatalf("with a server running: %v", err)
	}
	a.Close()
	if err := other.WithServersStopped(ctx, noop); err != nil {
		t.Fatalf("with the server stopped: %v", err)
	}
}
