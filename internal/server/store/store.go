// Package store is the Postgres persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when an insert violates a unique constraint.
var ErrDuplicate = errors.New("duplicate")

// DefaultTenantID is the single tenant used until multi-tenancy ships.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// DBTX is satisfied by both *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
}

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Queries runs statements against a pool or a transaction.
type Queries struct {
	db DBTX
}

// Open connects to Postgres and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Q returns Queries that run outside an explicit transaction.
func (s *Store) Q() *Queries { return &Queries{db: s.pool} }

// WithAdvisoryLock runs fn while holding the Postgres advisory lock id, and
// reports whether it ran. It reports false without running fn when another
// session already holds the lock, so a second replica skips the tick instead
// of queueing behind the first and repeating the work.
//
// The lock is session-scoped, so it is taken and released on one dedicated
// connection; releasing it from a different pooled connection would do nothing.
func (s *Store) WithAdvisoryLock(ctx context.Context, id int64, fn func(q *Queries) error) (bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&got); err != nil {
		return false, err
	}
	if !got {
		return false, nil
	}
	defer func() {
		// A fresh context: the caller's may already be cancelled, and the lock
		// must be released on this connection before it returns to the pool.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, id)
	}()
	return true, fn(&Queries{db: conn})
}

// InTx runs fn in a transaction, committing if fn returns nil.
func (s *Store) InTx(ctx context.Context, fn func(q *Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&Queries{db: tx})
	})
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
