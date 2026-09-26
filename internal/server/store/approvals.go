package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Approval kinds: what a held request would have done.
const (
	ApprovalCommand    = "command"
	ApprovalAssignment = "assignment"
	// ApprovalVersion makes a held version of a script, profile or app the
	// one devices receive.
	ApprovalVersion = "version"
	// ApprovalGroupMember adds a device to a static group that has code
	// assigned to it.
	ApprovalGroupMember = "group_member"
	// ApprovalGroupRule changes the rule of a dynamic group that has code
	// assigned to it.
	ApprovalGroupRule = "group_rule"
)

// Approval states.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
	// ApprovalFailed is approved, but the request could not be carried out
	// when replayed: the device was retired in the meantime, say.
	ApprovalFailed = "failed"
)

// ErrNotPending is deciding an approval someone already decided, or one that
// expired.
var ErrNotPending = errors.New("approval is no longer pending")

// Approval is a request held until a second administrator decides it.
type Approval struct {
	ID          uuid.UUID
	Kind        string
	Request     []byte
	Summary     string
	RequestedBy string
	RequesterID uuid.UUID
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Status      string
	DecidedBy   string
	DecidedAt   *time.Time
	Reason      string
	Result      []byte
}

const approvalCols = `id, kind, request, summary, requested_by, requester_id, created_at, expires_at,
	status, decided_by, decided_at, decision_reason, result`

func scanApproval(row pgx.Row) (Approval, error) {
	var a Approval
	err := row.Scan(&a.ID, &a.Kind, &a.Request, &a.Summary, &a.RequestedBy, &a.RequesterID,
		&a.CreatedAt, &a.ExpiresAt, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.Reason, &a.Result)
	return a, notFound(err)
}

// CreateApproval records a held request.
func (q *Queries) CreateApproval(ctx context.Context, a Approval) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO approvals (id, tenant_id, kind, request, summary, requested_by, requester_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.ID, DefaultTenantID, a.Kind, a.Request, a.Summary, a.RequestedBy, a.RequesterID, a.CreatedAt, a.ExpiresAt)
	return err
}

// ExpireApprovals marks every pending approval past its expiry expired.
// Expiry is applied lazily, before approvals are read or decided, rather
// than by a sweeper.
func (q *Queries) ExpireApprovals(ctx context.Context, now time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE approvals SET status = 'expired'
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2`, DefaultTenantID, now)
	return err
}

// GetApproval looks up one approval.
func (q *Queries) GetApproval(ctx context.Context, id uuid.UUID) (Approval, error) {
	return scanApproval(q.db.QueryRow(ctx,
		`SELECT `+approvalCols+` FROM approvals WHERE tenant_id = $1 AND id = $2`, DefaultTenantID, id))
}

// ListApprovals returns one page of approvals, newest first; status "" is
// every state.
func (q *Queries) ListApprovals(ctx context.Context, status string, page Page) ([]Approval, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+approvalCols+`, count(*) OVER () AS total FROM approvals
		WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4`, DefaultTenantID, status, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Approval
	total := 0
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.Kind, &a.Request, &a.Summary, &a.RequestedBy, &a.RequesterID,
			&a.CreatedAt, &a.ExpiresAt, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.Reason, &a.Result, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// DecideApproval moves a pending, unexpired approval to status. Only one
// decision wins: a second, or one after expiry, is ErrNotPending.
func (q *Queries) DecideApproval(ctx context.Context, id uuid.UUID, status, by, reason string, now time.Time) (Approval, error) {
	a, err := scanApproval(q.db.QueryRow(ctx, `
		UPDATE approvals SET status = $3, decided_by = $4, decision_reason = $5, decided_at = $6
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending' AND expires_at > $6
		RETURNING `+approvalCols, DefaultTenantID, id, status, by, reason, now))
	if errors.Is(err, ErrNotFound) {
		if _, err := q.GetApproval(ctx, id); err != nil {
			return Approval{}, err
		}
		return Approval{}, ErrNotPending
	}
	return a, err
}

// SetApprovalResult records what replaying an approved request did, and
// marks it failed if it could not be done.
func (q *Queries) SetApprovalResult(ctx context.Context, id uuid.UUID, status string, result []byte) error {
	_, err := q.db.Exec(ctx, `
		UPDATE approvals SET status = $3, result = $4 WHERE tenant_id = $1 AND id = $2`,
		DefaultTenantID, id, status, result)
	return err
}

// GroupMemberCount is how many devices are in a group now.
func (q *Queries) GroupMemberCount(ctx context.Context, groupID uuid.UUID) (int, error) {
	var n int
	err := q.db.QueryRow(ctx,
		`SELECT count(*) FROM group_members WHERE tenant_id = $1 AND group_id = $2`, DefaultTenantID, groupID).Scan(&n)
	return n, err
}

// LatestScriptVersion, LatestProfileVersion and LatestAppVersion are the
// highest version stored, which is past the current one while a newer
// version waits for approval. A new version is numbered after it.
func (q *Queries) LatestScriptVersion(ctx context.Context, id uuid.UUID) (int, error) {
	return q.latestVersion(ctx, `SELECT COALESCE(max(version), 0) FROM script_versions WHERE tenant_id = $1 AND script_id = $2`, id)
}

func (q *Queries) LatestProfileVersion(ctx context.Context, id uuid.UUID) (int, error) {
	return q.latestVersion(ctx, `SELECT COALESCE(max(version), 0) FROM profile_versions WHERE tenant_id = $1 AND profile_id = $2`, id)
}

func (q *Queries) LatestAppVersion(ctx context.Context, id uuid.UUID) (int, error) {
	return q.latestVersion(ctx, `SELECT COALESCE(max(version), 0) FROM app_versions WHERE tenant_id = $1 AND app_id = $2`, id)
}

func (q *Queries) latestVersion(ctx context.Context, query string, id uuid.UUID) (int, error) {
	var n int
	err := q.db.QueryRow(ctx, query, DefaultTenantID, id).Scan(&n)
	return n, err
}

// IsGroupMember reports whether a device is in a group now.
func (q *Queries) IsGroupMember(ctx context.Context, groupID, deviceID uuid.UUID) (bool, error) {
	var in bool
	err := q.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND device_id = $3)`,
		DefaultTenantID, groupID, deviceID).Scan(&in)
	return in, err
}

// ItemReach is how far an item's include assignments reach: the distinct
// devices in the static groups it is included in, and whether any of them is
// a dynamic group or All devices, which can grow to any size. Exclusions are
// not subtracted, so the count is never an underestimate.
func (q *Queries) ItemReach(ctx context.Context, itemKind string, itemID uuid.UUID) (devices int, unbounded bool, err error) {
	err = q.db.QueryRow(ctx, `
		SELECT
			COALESCE((SELECT bool_or(g.kind <> 'static')
				FROM assignments a JOIN device_groups g ON g.id = a.group_id
				WHERE a.tenant_id = $1 AND a.item_kind = $2 AND a.item_id = $3 AND a.mode = 'include'), false),
			(SELECT count(DISTINCT m.device_id)
				FROM assignments a JOIN group_members m ON m.group_id = a.group_id
				WHERE a.tenant_id = $1 AND a.item_kind = $2 AND a.item_id = $3 AND a.mode = 'include')`,
		DefaultTenantID, itemKind, itemID).Scan(&unbounded, &devices)
	return devices, unbounded, err
}

// GroupIncludesAnyOf reports whether a group has an include assignment of
// something other than the given kinds - code, in practice, rather than a
// policy that only reports or a window that only holds changes back.
func (q *Queries) GroupIncludesAnyOf(ctx context.Context, groupID uuid.UUID, exceptKinds []string) (bool, error) {
	var found bool
	err := q.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM assignments
			WHERE tenant_id = $1 AND group_id = $2 AND mode = 'include' AND NOT (item_kind = ANY($3)))`,
		DefaultTenantID, groupID, exceptKinds).Scan(&found)
	return found, err
}

// RecentCommandReach is how many distinct devices an administrator has sent
// commands of one type to since a moment, counting the devices of a request
// not yet made. Commands queued by approving a held request don't count:
// someone else has already looked at those.
func (q *Queries) RecentCommandReach(ctx context.Context, createdBy, typ string, since time.Time, adding []uuid.UUID) (int, error) {
	var n int
	err := q.db.QueryRow(ctx, `
		SELECT count(DISTINCT device_id) FROM (
			SELECT c.device_id FROM commands c
			WHERE c.tenant_id = $1 AND c.created_by = $2 AND c.type = $3 AND c.created_at >= $4
			  AND NOT EXISTS (
				SELECT 1 FROM approvals a,
					jsonb_array_elements(CASE WHEN jsonb_typeof(a.result->'commands') = 'array'
						THEN a.result->'commands' ELSE '[]'::jsonb END) e
				WHERE a.tenant_id = $1 AND a.kind = 'command' AND a.decided_at >= $4
				  AND e->>'id' = c.id::text)
			UNION ALL
			SELECT unnest($5::uuid[])
		) reached`, DefaultTenantID, createdBy, typ, since, adding).Scan(&n)
	return n, err
}
