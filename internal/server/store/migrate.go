package store

import (
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies all pending migrations. It takes an advisory lock, so
// concurrent server replicas are safe.
func Migrate(databaseURL string) error {
	return withMigrator(databaseURL, func(m *migrate.Migrate) error {
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("apply migrations: %w", err)
		}
		return nil
	})
}

// migrateTo moves the schema to exactly version, up or down. Tests use it to
// build a database as an earlier release left it.
func migrateTo(databaseURL string, version uint) error {
	return withMigrator(databaseURL, func(m *migrate.Migrate) error {
		if err := m.Migrate(version); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("migrate to %d: %w", version, err)
		}
		return nil
	})
}

// migrateDown reverts every migration.
func migrateDown(databaseURL string) error {
	return withMigrator(databaseURL, func(m *migrate.Migrate) error {
		if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("revert migrations: %w", err)
		}
		return nil
	})
}

// schemaVersion reports the applied migration version and whether a failed
// migration left the schema dirty.
func schemaVersion(databaseURL string) (version uint, dirty bool, err error) {
	err = withMigrator(databaseURL, func(m *migrate.Migrate) error {
		version, dirty, err = m.Version()
		return err
	})
	return version, dirty, err
}

// latestMigration is the highest migration version embedded in the binary.
func latestMigration() (uint, error) {
	src, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return 0, err
	}
	defer src.Close()
	v, err := src.First()
	if err != nil {
		return 0, err
	}
	for {
		next, err := src.Next(v)
		if err != nil {
			return v, nil
		}
		v = next
	}
}

func withMigrator(databaseURL string, fn func(*migrate.Migrate) error) error {
	src, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateURL(databaseURL))
	if err != nil {
		return fmt.Errorf("init migrations: %w", err)
	}
	defer m.Close()
	return fn(m)
}

// migrateURL rewrites a postgres:// URL to the pgx5:// scheme the
// golang-migrate pgx v5 driver registers.
func migrateURL(u string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(u, p) {
			return "pgx5://" + strings.TrimPrefix(u, p)
		}
	}
	return u
}
