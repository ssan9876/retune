package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// AgentVersion is one uploaded agent build.
type AgentVersion struct {
	ID        uuid.UUID
	Version   string
	SHA256    string
	SizeBytes int64
	Notes     string
	CreatedAt time.Time
	CreatedBy string
}

const agentVersionCols = `id, version, sha256, size_bytes, notes, created_at, created_by`

func scanAgentVersion(row pgx.Row) (AgentVersion, error) {
	var v AgentVersion
	err := row.Scan(&v.ID, &v.Version, &v.SHA256, &v.SizeBytes, &v.Notes, &v.CreatedAt, &v.CreatedBy)
	return v, notFound(err)
}

// CreateAgentVersion records an uploaded build. The version pre-check callers
// do first is racy against a concurrent upload of the same version, so the
// unique index on (tenant_id, version) is the real backstop: its violation is
// translated to ErrDuplicate rather than left as a raw pgx error.
func (q *Queries) CreateAgentVersion(ctx context.Context, v AgentVersion) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO agent_versions (id, tenant_id, version, sha256, size_bytes, notes, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		v.ID, DefaultTenantID, v.Version, v.SHA256, v.SizeBytes, v.Notes, v.CreatedAt, v.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

// GetAgentVersion looks up a build by its id.
func (q *Queries) GetAgentVersion(ctx context.Context, id uuid.UUID) (AgentVersion, error) {
	return scanAgentVersion(q.db.QueryRow(ctx, `SELECT `+agentVersionCols+` FROM agent_versions WHERE id = $1`, id))
}

// GetAgentVersionByVersion looks up a build by its version string.
func (q *Queries) GetAgentVersionByVersion(ctx context.Context, version string) (AgentVersion, error) {
	return scanAgentVersion(q.db.QueryRow(ctx,
		`SELECT `+agentVersionCols+` FROM agent_versions WHERE tenant_id = $1 AND version = $2`,
		DefaultTenantID, version))
}

// ListAgentVersions returns one page of uploaded builds, newest first.
func (q *Queries) ListAgentVersions(ctx context.Context, page Page) ([]AgentVersion, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+agentVersionCols+`, count(*) OVER () AS total FROM agent_versions
		WHERE tenant_id = $1
		-- The id breaks ties: two uploads can share a timestamp, and UUIDv7
		-- sorts by creation time, so the newer row still comes first.
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3`, DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AgentVersion
	total := 0
	for rows.Next() {
		var v AgentVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.SHA256, &v.SizeBytes, &v.Notes,
			&v.CreatedAt, &v.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// DeleteAgentVersion removes an uploaded build's metadata.
func (q *Queries) DeleteAgentVersion(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM agent_versions WHERE id = $1`, id)
	return err
}
