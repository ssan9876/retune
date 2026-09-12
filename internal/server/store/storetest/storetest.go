// Package storetest starts disposable Postgres databases for tests.
package storetest

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"retune/internal/server/store"
)

// DatabaseURL starts a fresh Postgres 17 container and returns its URL.
// The database is empty (not migrated). Skipped under -short.
func DatabaseURL(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in -short mode")
	}
	// On Windows, testcontainers detects Docker by os.Stat-ing the named pipe,
	// which fails with "All pipe instances are busy" when several test
	// binaries start at once, and it caches that failure for the process.
	// Naming the host skips the stat; the Docker client's pipe dialer waits
	// for a free instance instead of failing.
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		os.Setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("retune"),
		postgres.WithUsername("retune"),
		postgres.WithPassword("retune"),
		postgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start postgres (is Docker running?): %v", err)
	}
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	return url
}

// New returns a migrated, open Store backed by a fresh container.
func New(t *testing.T) *store.Store {
	t.Helper()
	url := DatabaseURL(t)
	if err := store.Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}
