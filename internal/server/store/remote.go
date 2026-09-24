package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"retune/internal/protocol"
)

// Remote session states.
const (
	RemoteWaiting = "waiting"
	RemoteActive  = "active"
	RemoteEnded   = "ended"
)

// RemoteSession is an administrator's interactive shell on a device.
type RemoteSession struct {
	ID        uuid.UUID
	DeviceID  uuid.UUID
	StartedBy string
	Reason    string
	Status    string
	CreatedAt time.Time
	StartedAt *time.Time
	EndedAt   *time.Time
	EndReason string
}

const remoteCols = `id, device_id, started_by, reason, status, created_at, started_at, ended_at, end_reason`

func scanRemote(row pgx.Row) (RemoteSession, error) {
	var r RemoteSession
	err := row.Scan(&r.ID, &r.DeviceID, &r.StartedBy, &r.Reason, &r.Status, &r.CreatedAt, &r.StartedAt, &r.EndedAt, &r.EndReason)
	return r, notFound(err)
}

// CreateRemoteSession stores a new session, waiting for its device.
func (q *Queries) CreateRemoteSession(ctx context.Context, r RemoteSession) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO remote_sessions (id, tenant_id, device_id, started_by, reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		r.ID, DefaultTenantID, r.DeviceID, r.StartedBy, r.Reason, r.CreatedAt)
	return err
}

// GetRemoteSession looks up one session.
func (q *Queries) GetRemoteSession(ctx context.Context, id uuid.UUID) (RemoteSession, error) {
	return scanRemote(q.db.QueryRow(ctx,
		`SELECT `+remoteCols+` FROM remote_sessions WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id))
}

// ListRemoteSessions returns a device's sessions, newest first.
func (q *Queries) ListRemoteSessions(ctx context.Context, deviceID uuid.UUID, page Page) ([]RemoteSession, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+remoteCols+`, count(*) OVER () FROM remote_sessions
		WHERE tenant_id = $1 AND device_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		DefaultTenantID, deviceID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RemoteSession
	total := 0
	for rows.Next() {
		var r RemoteSession
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.StartedBy, &r.Reason, &r.Status, &r.CreatedAt, &r.StartedAt,
			&r.EndedAt, &r.EndReason, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// MarkRemoteSessionActive records that the device has joined.
func (q *Queries) MarkRemoteSessionActive(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE remote_sessions SET status = 'active', started_at = $3
		WHERE tenant_id = $1 AND id = $2 AND status = 'waiting'`, DefaultTenantID, id, at)
	return err
}

// EndRemoteSession ends a session, and reports whether it was this call
// that ended it. Anyone waiting on it is woken.
func (q *Queries) EndRemoteSession(ctx context.Context, id uuid.UUID, reason string, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE remote_sessions SET status = 'ended', ended_at = $3, end_reason = $4
		WHERE tenant_id = $1 AND id = $2 AND status <> 'ended'`, DefaultTenantID, id, at, reason)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	return true, q.Wake(ctx, "session:"+id.String())
}

// AppendRemoteChunk adds to a session's transcript, and wakes whoever is
// waiting for it.
func (q *Queries) AppendRemoteChunk(ctx context.Context, sessionID uuid.UUID, stream, data string, at time.Time) error {
	if _, err := q.db.Exec(ctx, `
		INSERT INTO remote_session_chunks (session_id, stream, data, at) VALUES ($1, $2, $3, $4)`,
		sessionID, stream, data, at); err != nil {
		return err
	}
	return q.Wake(ctx, "session:"+sessionID.String())
}

// RemoteChunks returns a session's chunks after seq, in order: only the
// streams named, or all of them when none are.
func (q *Queries) RemoteChunks(ctx context.Context, sessionID uuid.UUID, after int64, streams []string, limit int) ([]protocol.RemoteChunk, error) {
	if streams == nil {
		streams = []string{}
	}
	rows, err := q.db.Query(ctx, `
		SELECT seq, stream, data, at FROM remote_session_chunks
		WHERE session_id = $1 AND seq > $2 AND (cardinality($3::text[]) = 0 OR stream = ANY($3))
		ORDER BY seq LIMIT $4`, sessionID, after, streams, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []protocol.RemoteChunk{}
	for rows.Next() {
		var c protocol.RemoteChunk
		if err := rows.Scan(&c.Seq, &c.Stream, &c.Data, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LastRemoteInput is when an administrator last typed into a session, or
// its start if nobody has.
func (q *Queries) LastRemoteInput(ctx context.Context, sessionID uuid.UUID) (time.Time, error) {
	var at time.Time
	err := q.db.QueryRow(ctx, `
		SELECT coalesce((SELECT max(at) FROM remote_session_chunks WHERE session_id = $1 AND stream = 'in'),
		                (SELECT coalesce(started_at, created_at) FROM remote_sessions WHERE id = $1))`,
		sessionID).Scan(&at)
	return at, err
}
