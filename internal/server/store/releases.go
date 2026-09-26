package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Release is a release the release feed found and verified.
type Release struct {
	ID          uuid.UUID
	Version     string
	Prerelease  bool
	PublishedAt time.Time
	Notes       string
	// Manifest is release.json's exact bytes, and Signature its sidecar.
	Manifest   []byte
	Signature  []byte
	KeyID      string
	VerifiedAt time.Time
	// AgentVersionID is the agent build imported from it, once imported.
	AgentVersionID *uuid.UUID
	ImportError    string
}

const releaseCols = `id, version, prerelease, published_at, notes, manifest, signature, key_id, verified_at,
	agent_version_id, import_error`

func scanRelease(row pgx.Row) (Release, error) {
	var r Release
	err := row.Scan(&r.ID, &r.Version, &r.Prerelease, &r.PublishedAt, &r.Notes, &r.Manifest, &r.Signature,
		&r.KeyID, &r.VerifiedAt, &r.AgentVersionID, &r.ImportError)
	return r, notFound(err)
}

// CreateRelease records a verified release. A version already recorded is
// left as it is, and created is false.
func (q *Queries) CreateRelease(ctx context.Context, r Release) (created bool, err error) {
	tag, err := q.db.Exec(ctx, `
		INSERT INTO releases (id, tenant_id, version, prerelease, published_at, notes, manifest, signature, key_id, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, version) DO NOTHING`,
		r.ID, DefaultTenantID, r.Version, r.Prerelease, r.PublishedAt, r.Notes, r.Manifest, r.Signature, r.KeyID, r.VerifiedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// GetReleaseByVersion looks up a recorded release.
func (q *Queries) GetReleaseByVersion(ctx context.Context, version string) (Release, error) {
	return scanRelease(q.db.QueryRow(ctx,
		`SELECT `+releaseCols+` FROM releases WHERE tenant_id = $1 AND version = $2`, DefaultTenantID, version))
}

// ListReleases returns every recorded release, newest published first. There
// are a handful a year, so there is no paging.
func (q *Queries) ListReleases(ctx context.Context) ([]Release, error) {
	rows, err := q.db.Query(ctx, `
		SELECT `+releaseCols+` FROM releases WHERE tenant_id = $1
		ORDER BY published_at DESC, id DESC`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		r, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetReleaseImport records the outcome of importing a release's agent build.
func (q *Queries) SetReleaseImport(ctx context.Context, id uuid.UUID, agentVersionID *uuid.UUID, importError string) error {
	_, err := q.db.Exec(ctx, `
		UPDATE releases SET agent_version_id = $3, import_error = $4 WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, id, agentVersionID, importError)
	return err
}

// ReleaseFeedState is when the feed last looked, and what failed if it did.
type ReleaseFeedState struct {
	CheckedAt *time.Time
	Error     string
}

// GetReleaseFeedState reads the feed's last check. Never checked is the zero value.
func (q *Queries) GetReleaseFeedState(ctx context.Context) (ReleaseFeedState, error) {
	var s ReleaseFeedState
	err := q.db.QueryRow(ctx,
		`SELECT checked_at, error FROM release_feed_state WHERE tenant_id = $1`, DefaultTenantID).Scan(&s.CheckedAt, &s.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReleaseFeedState{}, nil
	}
	return s, err
}

// SetReleaseFeedState records a check.
func (q *Queries) SetReleaseFeedState(ctx context.Context, checkedAt time.Time, checkErr string) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO release_feed_state (tenant_id, checked_at, error) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET checked_at = EXCLUDED.checked_at, error = EXCLUDED.error`,
		DefaultTenantID, checkedAt, checkErr)
	return err
}

// AgentRolloutPolicy is how imported agent builds reach the fleet.
type AgentRolloutPolicy struct {
	Enabled      bool
	PilotGroupID *uuid.UUID
	DelayHours   int
	UpdatedAt    time.Time
	UpdatedBy    string
}

// DefaultRolloutDelayHours is the pilot's delay when nobody has set one.
const DefaultRolloutDelayHours = 24

// GetAgentRolloutPolicy reads the policy; never set is off.
func (q *Queries) GetAgentRolloutPolicy(ctx context.Context) (AgentRolloutPolicy, error) {
	var p AgentRolloutPolicy
	err := q.db.QueryRow(ctx, `
		SELECT enabled, pilot_group_id, delay_hours, updated_at, updated_by
		FROM agent_rollout_policy WHERE tenant_id = $1`, DefaultTenantID).
		Scan(&p.Enabled, &p.PilotGroupID, &p.DelayHours, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentRolloutPolicy{DelayHours: DefaultRolloutDelayHours}, nil
	}
	return p, err
}

// SetAgentRolloutPolicy replaces the policy.
func (q *Queries) SetAgentRolloutPolicy(ctx context.Context, p AgentRolloutPolicy) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO agent_rollout_policy (tenant_id, enabled, pilot_group_id, delay_hours, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, pilot_group_id = EXCLUDED.pilot_group_id,
		    delay_hours = EXCLUDED.delay_hours, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		DefaultTenantID, p.Enabled, p.PilotGroupID, p.DelayHours, p.UpdatedAt, p.UpdatedBy)
	return err
}

// Agent rollout states.
const (
	// RolloutPilot: assigned (or waiting to be) to the pilot group, and
	// watched for the delay.
	RolloutPilot = "pilot"
	// RolloutPromoting: the pilot passed; the fleet-wide assignment waits for
	// approval.
	RolloutPromoting = "promoting"
	// RolloutPromoted: every device has it.
	RolloutPromoted = "promoted"
	// RolloutHalted: stopped, and Detail says why.
	RolloutHalted = "halted"
	// RolloutSuperseded: a newer build took its place.
	RolloutSuperseded = "superseded"
)

// AgentRollout is one automatic rollout of one build.
type AgentRollout struct {
	ID                  uuid.UUID
	AgentVersionID      uuid.UUID
	State               string
	PilotGroupID        *uuid.UUID
	DelayHours          int
	PilotAssignmentID   *uuid.UUID
	PilotApprovalID     *uuid.UUID
	PilotStartedAt      *time.Time
	ExcludeAssignmentID *uuid.UUID
	FleetAssignmentID   *uuid.UUID
	FleetApprovalID     *uuid.UUID
	PromotedAt          *time.Time
	Detail              string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	// Version is the build's version string, read with the rollout.
	Version string
}

// Active reports whether a rollout still has work to do.
func (r AgentRollout) Active() bool { return r.State == RolloutPilot || r.State == RolloutPromoting }

const rolloutCols = `r.id, r.agent_version_id, r.state, r.pilot_group_id, r.delay_hours, r.pilot_assignment_id,
	r.pilot_approval_id, r.pilot_started_at, r.exclude_assignment_id, r.fleet_assignment_id, r.fleet_approval_id,
	r.promoted_at, r.detail, r.created_at, r.updated_at, v.version`

const rolloutFrom = ` FROM agent_rollouts r JOIN agent_versions v ON v.id = r.agent_version_id AND v.tenant_id = r.tenant_id`

func scanRollout(row pgx.Row) (AgentRollout, error) {
	var r AgentRollout
	err := row.Scan(&r.ID, &r.AgentVersionID, &r.State, &r.PilotGroupID, &r.DelayHours, &r.PilotAssignmentID,
		&r.PilotApprovalID, &r.PilotStartedAt, &r.ExcludeAssignmentID, &r.FleetAssignmentID, &r.FleetApprovalID,
		&r.PromotedAt, &r.Detail, &r.CreatedAt, &r.UpdatedAt, &r.Version)
	return r, notFound(err)
}

// CreateAgentRollout starts a rollout. A build already rolled out is left
// alone, and created is false.
func (q *Queries) CreateAgentRollout(ctx context.Context, r AgentRollout) (created bool, err error) {
	tag, err := q.db.Exec(ctx, `
		INSERT INTO agent_rollouts (id, tenant_id, agent_version_id, state, pilot_group_id, delay_hours, detail, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (tenant_id, agent_version_id) DO NOTHING`,
		r.ID, DefaultTenantID, r.AgentVersionID, r.State, r.PilotGroupID, r.DelayHours, r.Detail, r.CreatedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// UpdateAgentRollout writes back everything a rollout's step can change.
func (q *Queries) UpdateAgentRollout(ctx context.Context, r AgentRollout) error {
	_, err := q.db.Exec(ctx, `
		UPDATE agent_rollouts SET state = $3, pilot_assignment_id = $4, pilot_approval_id = $5, pilot_started_at = $6,
		    exclude_assignment_id = $7, fleet_assignment_id = $8, fleet_approval_id = $9, promoted_at = $10,
		    detail = $11, updated_at = $12
		WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, r.ID, r.State, r.PilotAssignmentID, r.PilotApprovalID, r.PilotStartedAt,
		r.ExcludeAssignmentID, r.FleetAssignmentID, r.FleetApprovalID, r.PromotedAt, r.Detail, r.UpdatedAt)
	return err
}

// GetAgentRollout looks up one rollout.
func (q *Queries) GetAgentRollout(ctx context.Context, id uuid.UUID) (AgentRollout, error) {
	return scanRollout(q.db.QueryRow(ctx, `SELECT `+rolloutCols+rolloutFrom+` WHERE r.tenant_id = $1 AND r.id = $2`,
		DefaultTenantID, id))
}

// ListAgentRollouts returns the most recent rollouts, newest first.
func (q *Queries) ListAgentRollouts(ctx context.Context, limit int) ([]AgentRollout, error) {
	return q.rollouts(ctx, `SELECT `+rolloutCols+rolloutFrom+`
		WHERE r.tenant_id = $1 ORDER BY r.created_at DESC, r.id DESC LIMIT $2`, DefaultTenantID, limit)
}

// ListRolloutsInState returns the rollouts in any of states, oldest first.
func (q *Queries) ListRolloutsInState(ctx context.Context, states ...string) ([]AgentRollout, error) {
	return q.rollouts(ctx, `SELECT `+rolloutCols+rolloutFrom+`
		WHERE r.tenant_id = $1 AND r.state = ANY($2) ORDER BY r.created_at, r.id`, DefaultTenantID, states)
}

func (q *Queries) rollouts(ctx context.Context, sql string, args ...any) ([]AgentRollout, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentRollout
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAssignmentFor finds the assignment of one item to one group, in one mode.
func (q *Queries) GetAssignmentFor(ctx context.Context, itemKind string, itemID, groupID uuid.UUID, mode string) (Assignment, error) {
	return scanAssignment(q.db.QueryRow(ctx, `
		SELECT `+assignmentCols+` FROM assignments
		WHERE tenant_id = $1 AND item_kind = $2 AND item_id = $3 AND group_id = $4 AND mode = $5`,
		DefaultTenantID, itemKind, itemID, groupID, mode))
}

// PilotHealth is how an agent build is doing on a group's devices.
type PilotHealth struct {
	// Succeeded devices report running it; Failed ones rolled back or failed
	// to install it.
	Succeeded int
	Failed    int
	// Failures names the failed devices and why, a few at most.
	Failures []string
}

// AgentBuildHealth reports an agent build's status on a group's active
// devices, from the statuses devices report.
func (q *Queries) AgentBuildHealth(ctx context.Context, groupID, agentVersionID uuid.UUID) (PilotHealth, error) {
	rows, err := q.db.Query(ctx, `
		SELECT s.status, d.hostname, s.detail
		FROM group_members m
		JOIN devices d ON d.id = m.device_id AND d.tenant_id = m.tenant_id
		JOIN device_item_status s ON s.device_id = m.device_id AND s.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.group_id = $2 AND d.status = $3
		  AND s.item_kind = 'agent' AND s.item_id = $4
		ORDER BY lower(d.hostname), d.id`, DefaultTenantID, groupID, DeviceActive, agentVersionID)
	if err != nil {
		return PilotHealth{}, err
	}
	defer rows.Close()
	var h PilotHealth
	for rows.Next() {
		var status, host, detail string
		if err := rows.Scan(&status, &host, &detail); err != nil {
			return PilotHealth{}, err
		}
		switch status {
		case ItemSucceeded:
			h.Succeeded++
		case ItemFailed:
			h.Failed++
			if len(h.Failures) < 5 {
				if detail != "" {
					host += " (" + detail + ")"
				}
				h.Failures = append(h.Failures, host)
			}
		}
	}
	return h, rows.Err()
}

// FiringHaltedRollouts is one alert subject per halted rollout.
func (q *Queries) FiringHaltedRollouts(ctx context.Context) ([]AlertSubject, error) {
	return q.alertSubjects(ctx, `
		SELECT 'rollout:' || r.id, 'agent ' || v.version || ' rollout halted' ||
		           CASE WHEN r.detail = '' THEN '' ELSE ' - ' || left(r.detail, 200) END
		FROM agent_rollouts r JOIN agent_versions v ON v.id = r.agent_version_id AND v.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND r.state = $2
		ORDER BY r.created_at`, DefaultTenantID, RolloutHalted)
}
