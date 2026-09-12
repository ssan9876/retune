// Package store is the Postgres persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("not found")

// DefaultTenantID is the single tenant used until multi-tenancy ships.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// DBTX is satisfied by both *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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
