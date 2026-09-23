package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CommandArtifact is a file a command produced.
type CommandArtifact struct {
	CommandID uuid.UUID
	SizeBytes int64
	SHA256    string
	CreatedAt time.Time
}

// InsertCommandArtifact records a command's file. A second one for the same
// command is ErrDuplicate.
func (q *Queries) InsertCommandArtifact(ctx context.Context, a CommandArtifact) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO command_artifacts (command_id, tenant_id, size_bytes, sha256, created_at)
		VALUES ($1, $2, $3, $4, $5)`, a.CommandID, DefaultTenantID, a.SizeBytes, a.SHA256, a.CreatedAt)
	return duplicate(err)
}

// GetCommandArtifact returns a command's file record.
func (q *Queries) GetCommandArtifact(ctx context.Context, commandID uuid.UUID) (CommandArtifact, error) {
	var a CommandArtifact
	err := q.db.QueryRow(ctx, `
		SELECT command_id, size_bytes, sha256, created_at FROM command_artifacts
		WHERE tenant_id = $1 AND command_id = $2`, DefaultTenantID, commandID).
		Scan(&a.CommandID, &a.SizeBytes, &a.SHA256, &a.CreatedAt)
	return a, notFound(err)
}

// DeleteCommandArtifactsBefore removes the records of files older than
// before, in any tenant, and returns whose they were so the files can go
// too.
func (q *Queries) DeleteCommandArtifactsBefore(ctx context.Context, before time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := q.db.Query(ctx, `
		DELETE FROM command_artifacts WHERE command_id IN (
			SELECT command_id FROM command_artifacts WHERE created_at < $1 ORDER BY created_at LIMIT $2)
		RETURNING command_id`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CommandArtifactExists reports whether a command's file is on record, in
// any tenant.
func (q *Queries) CommandArtifactExists(ctx context.Context, commandID uuid.UUID) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM command_artifacts WHERE command_id = $1)`, commandID).Scan(&ok)
	return ok, err
}

// DeleteCommandArtifact removes one command's file record.
func (q *Queries) DeleteCommandArtifact(ctx context.Context, commandID uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`DELETE FROM command_artifacts WHERE tenant_id = $1 AND command_id = $2`, DefaultTenantID, commandID)
	return err
}
