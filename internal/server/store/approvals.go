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
