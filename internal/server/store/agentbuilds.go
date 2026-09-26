package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// AgentVersionBuild is one platform's build of an agent version: its own
// bytes, hash and release signature.
type AgentVersionBuild struct {
	AgentVersionID uuid.UUID
	Platform       string
	SHA256         string
	SizeBytes      int64
	KeyID          string
	Signature      string
	CreatedAt      time.Time
	CreatedBy      string
}

const agentBuildCols = `agent_version_id, platform, sha256, size_bytes, key_id, signature, created_at, created_by`

// CreateAgentVersionBuild records one platform's build of a version. A second
// build for the same platform is ErrDuplicate: builds are immutable.
func (q *Queries) CreateAgentVersionBuild(ctx context.Context, b AgentVersionBuild) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO agent_version_builds (agent_version_id, tenant_id, platform, sha256, size_bytes, key_id, signature, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		b.AgentVersionID, DefaultTenantID, b.Platform, b.SHA256, b.SizeBytes, b.KeyID, b.Signature, b.CreatedAt, b.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

// GetAgentVersionBuild returns a version's build for one platform.
func (q *Queries) GetAgentVersionBuild(ctx context.Context, versionID uuid.UUID, platform string) (AgentVersionBuild, error) {
	var b AgentVersionBuild
	err := q.db.QueryRow(ctx, `SELECT `+agentBuildCols+` FROM agent_version_builds
		WHERE tenant_id = $1 AND agent_version_id = $2 AND platform = $3`, DefaultTenantID, versionID, platform).
		Scan(&b.AgentVersionID, &b.Platform, &b.SHA256, &b.SizeBytes, &b.KeyID, &b.Signature, &b.CreatedAt, &b.CreatedBy)
	return b, notFound(err)
}

// ListAgentVersionBuilds returns the builds of each of the given versions,
// by version, each version's in platform order.
func (q *Queries) ListAgentVersionBuilds(ctx context.Context, versionIDs []uuid.UUID) (map[uuid.UUID][]AgentVersionBuild, error) {
	out := map[uuid.UUID][]AgentVersionBuild{}
	if len(versionIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.Query(ctx, `SELECT `+agentBuildCols+` FROM agent_version_builds
		WHERE tenant_id = $1 AND agent_version_id = ANY($2) ORDER BY agent_version_id, platform`,
		DefaultTenantID, versionIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b AgentVersionBuild
		if err := rows.Scan(&b.AgentVersionID, &b.Platform, &b.SHA256, &b.SizeBytes, &b.KeyID, &b.Signature, &b.CreatedAt, &b.CreatedBy); err != nil {
			return nil, err
		}
		out[b.AgentVersionID] = append(out[b.AgentVersionID], b)
	}
	return out, rows.Err()
}

// RecordCheckinPlatform is RecordCheckin that also stores what the agent runs
// on. An empty platform -- an agent too old to report one -- leaves whatever
// was stored before.
func (q *Queries) RecordCheckinPlatform(ctx context.Context, tenantID, id uuid.UUID, agentVersion, platform string, at time.Time) error {
	_, err := q.db.Exec(ctx,
		`UPDATE devices SET last_seen_at = $3, agent_version = $4, platform = COALESCE(NULLIF($5, ''), platform)
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, agentVersion, platform)
	return err
}

// GetDevicePlatform returns the platform a device's agent last reported, ""
// if it never has.
func (q *Queries) GetDevicePlatform(ctx context.Context, id uuid.UUID) (string, error) {
	var p string
	err := q.db.QueryRow(ctx, `SELECT platform FROM devices WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id).Scan(&p)
	return p, notFound(err)
}
