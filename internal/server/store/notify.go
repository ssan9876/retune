package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// WakeChannel is the Postgres notification channel for "something is
// waiting": a command for a device, input for a remote session. Every
// server listens on it, so whichever one holds a waiting request answers it.
const WakeChannel = "retune_wake"

// Wake notifies every server that key has something new. Inside a
// transaction the notification is sent when it commits, and not at all if
// it rolls back.
func (q *Queries) Wake(ctx context.Context, key string) error {
	_, err := q.db.Exec(ctx, `SELECT pg_notify($1, $2)`, WakeChannel, key)
	return err
}

// Listen calls fn with the payload of every notification on channel until
// ctx ends, on a connection of its own, reconnecting after a failure. A
// notification sent while it was reconnecting is lost, which a waiter
// survives: it waits only so long before looking for itself.
func (s *Store) Listen(ctx context.Context, channel string, fn func(payload string)) {
	backoff := time.Second
	for ctx.Err() == nil {
		// It only returns when the connection failed, or ctx ended: either
		// way, reconnect unless ctx is done.
		_ = s.listenOnce(ctx, channel, fn)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (s *Store) listenOnce(ctx context.Context, channel string, fn func(string)) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		fn(n.Payload)
	}
}
