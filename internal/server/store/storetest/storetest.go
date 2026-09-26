// Package storetest hands out disposable Postgres databases for tests.
//
// A test binary starts one Postgres 17 container, the first time a test asks
// for a database, and migrates a template database in it once. Every test
// then gets its own database cloned from that template: as isolated as a
// container of its own, for a few milliseconds instead of a few seconds of
// container start and migrations. Testcontainers' reaper removes the
// container when the test binary exits.
package storetest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"retune/internal/server/store"
)

const templateDB = "retune_template"

var (
	serverMu  sync.Mutex
	serverURL string // the container's maintenance database, "postgres"; empty until started
	admin     *pgxpool.Pool

	templateOnce sync.Once
	templateErr  error

	seq atomic.Int64
)

// DatabaseURL returns the URL of a new database with the current schema
// already migrated. Migrating it again is a no-op. Skipped under -short.
func DatabaseURL(t *testing.T) string {
	t.Helper()
	start(t)
	templateOnce.Do(func() { templateErr = makeTemplate() })
	if templateErr != nil {
		t.Fatalf("migrate the template database: %v", templateErr)
	}
	return create(t, "TEMPLATE "+templateDB)
}

// EmptyDatabaseURL returns the URL of a new, empty database (not migrated),
// for tests of the migrations themselves. Skipped under -short.
func EmptyDatabaseURL(t *testing.T) string {
	t.Helper()
	start(t)
	return create(t, "")
}

// New returns an open store on a new, migrated database.
func New(t *testing.T) *store.Store {
	t.Helper()
	url := DatabaseURL(t)
	s, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// start starts the shared container, once per test binary.
func start(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in -short mode")
	}
	serverMu.Lock()
	defer serverMu.Unlock()
	if serverURL != "" {
		return
	}
	// Starting pulls images, and a registry that drops one connection must not
	// fail every test in the package: try again a few times before giving up.
	var err error
	for attempt := 1; attempt <= 4; attempt++ {
		if err = startServer(); err == nil {
			return
		}
		serverURL = ""
		if admin != nil {
			admin.Close()
			admin = nil
		}
		time.Sleep(time.Duration(attempt) * 5 * time.Second)
	}
	t.Fatalf("start postgres (is Docker running?): %v", err)
}

func startServer() error {
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
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("retune"),
		postgres.WithPassword("retune"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return err
	}
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return err
	}
	if admin, err = pgxpool.New(ctx, url); err != nil {
		return err
	}
	serverURL = url
	// Durability buys nothing in a container thrown away at exit.
	_, err = admin.Exec(ctx, `ALTER SYSTEM SET fsync = off`)
	if err == nil {
		_, err = admin.Exec(ctx, `ALTER SYSTEM SET synchronous_commit = off`)
	}
	if err == nil {
		_, err = admin.Exec(ctx, `SELECT pg_reload_conf()`)
	}
	return err
}

func makeTemplate() error {
	ctx := context.Background()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+templateDB); err != nil {
		return err
	}
	return store.Migrate(withDatabase(serverURL, templateDB))
}

// create makes a database for one test and drops it when the test ends.
func create(t *testing.T, clause string) string {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("test_%d_%d", os.Getpid(), seq.Add(1))
	ident := pgx.Identifier{name}.Sanitize()
	var err error
	// Cloning fails while anything is still connected to the template; the
	// migration's connection can take a moment to go.
	for try := 0; try < 50; try++ {
		if _, err = admin.Exec(ctx, "CREATE DATABASE "+ident+" "+clause); err == nil ||
			!strings.Contains(err.Error(), "being accessed by other users") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}
	// Registered before the test's own cleanups, so it runs after them; FORCE
	// covers a pool the test left open.
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	})
	return withDatabase(serverURL, name)
}

func withDatabase(raw, name string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + name
	return u.String()
}
