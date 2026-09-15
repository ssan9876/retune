package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Compliance states. The first three are what device_compliance rows hold;
// not_evaluated only ever appears as a derived overall state (no assigned
// policy has scored the device at all).
const (
	ComplianceCompliant    = "compliant"
	ComplianceNonCompliant = "non_compliant"
	ComplianceUnknown      = "unknown"
	ComplianceNotEvaluated = "not_evaluated"
)

// complianceRank orders states worst-first so the overall state for a device
// is just "the highest-ranked state across its rows".
var complianceRank = map[string]int{
	ComplianceCompliant:    0,
	ComplianceUnknown:      1,
	ComplianceNonCompliant: 2,
}

// CompliancePolicy states what a healthy device looks like. It has no
// versions: it is edited in place and devices are simply re-evaluated.
type CompliancePolicy struct {
	ID          uuid.UUID
	Name        string
	Description string
	Rules       []byte // raw JSON array; parsing lives in internal/server/compliance
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
}

const compliancePolicyCols = `id, name, description, rules, created_at, updated_at, created_by`

func scanCompliancePolicy(row pgx.Row) (CompliancePolicy, error) {
	var p CompliancePolicy
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Rules, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy)
	return p, notFound(err)
}

// CreateCompliancePolicy inserts a new policy. The unique index on
// (tenant_id, name) is what actually stops a duplicate; its violation comes
// back as ErrDuplicate rather than a raw pgx error, matching CreateAgentVersion.
func (q *Queries) CreateCompliancePolicy(ctx context.Context, p CompliancePolicy) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO compliance_policies (id, tenant_id, name, description, rules, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		p.ID, DefaultTenantID, p.Name, p.Description, p.Rules, p.CreatedAt, p.UpdatedAt, p.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

// GetCompliancePolicy looks up a policy by id.
func (q *Queries) GetCompliancePolicy(ctx context.Context, tenantID, id uuid.UUID) (CompliancePolicy, error) {
	return scanCompliancePolicy(q.db.QueryRow(ctx,
		`SELECT `+compliancePolicyCols+` FROM compliance_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// ListCompliancePolicies returns one page of policies, alphabetically.
func (q *Queries) ListCompliancePolicies(ctx context.Context, page Page) ([]CompliancePolicy, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+compliancePolicyCols+`, count(*) OVER () AS total FROM compliance_policies
		WHERE tenant_id = $1
		ORDER BY lower(name)
		LIMIT $2 OFFSET $3`, DefaultTenantID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CompliancePolicy
	total := 0
	for rows.Next() {
		var v CompliancePolicy
		if err := rows.Scan(&v.ID, &v.Name, &v.Description, &v.Rules, &v.CreatedAt, &v.UpdatedAt, &v.CreatedBy, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// UpdateCompliancePolicy replaces a policy's editable fields in place.
func (q *Queries) UpdateCompliancePolicy(ctx context.Context, tenantID uuid.UUID, p CompliancePolicy) error {
	_, err := q.db.Exec(ctx, `
		UPDATE compliance_policies SET name = $3, description = $4, rules = $5, updated_at = $6
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, p.ID, p.Name, p.Description, p.Rules, p.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

// DeleteCompliancePolicy removes a policy; its device_compliance rows cascade.
// Callers are still responsible for the mirrored device_item_status rows and
// group assignments, neither of which has a foreign key to cascade through.
func (q *Queries) DeleteCompliancePolicy(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM compliance_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// DeviceCompliance is one policy's latest result on one device.
type DeviceCompliance struct {
	DeviceID uuid.UUID
	PolicyID uuid.UUID
	// Hostname is filled in by the listing queries only, not by UpsertDeviceCompliance.
	Hostname    string
	State       string
	Failures    []byte // JSON array of {rule, state, detail}
	EvaluatedAt time.Time
}

// UpsertDeviceCompliance records one policy's latest verdict for one device.
func (q *Queries) UpsertDeviceCompliance(ctx context.Context, dc DeviceCompliance) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_compliance (device_id, policy_id, tenant_id, state, failures, evaluated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (device_id, policy_id) DO UPDATE
		SET state = EXCLUDED.state, failures = EXCLUDED.failures, evaluated_at = EXCLUDED.evaluated_at`,
		dc.DeviceID, dc.PolicyID, DefaultTenantID, dc.State, dc.Failures, dc.EvaluatedAt)
	return err
}

// DeleteDeviceComplianceExcept removes a device's results for every policy not
// in keep. Evaluation calls this after scoring the policies that still apply,
// so a policy that was unassigned (or excluded) from the device loses its now
// stale row instead of it lingering forever. An empty/nil keep means no
// policy applies any more, so every row for the device is removed.
func (q *Queries) DeleteDeviceComplianceExcept(ctx context.Context, deviceID uuid.UUID, keep []uuid.UUID) error {
	if keep == nil {
		// pgx sends a nil slice as SQL NULL, and ANY(NULL) is NULL rather than
		// false, which would make the NOT (...) predicate match nothing and
		// leave every row in place instead of clearing them all.
		keep = []uuid.UUID{}
	}
	_, err := q.db.Exec(ctx, `
		DELETE FROM device_compliance WHERE device_id = $1 AND NOT (policy_id = ANY($2))`,
		deviceID, keep)
	return err
}

// DeleteComplianceForPolicy removes every device's result for one policy,
// used when a policy is deleted outright (in the same transaction as the
// policy row and its mirrored item-status rows).
func (q *Queries) DeleteComplianceForPolicy(ctx context.Context, policyID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM device_compliance WHERE policy_id = $1`, policyID)
	return err
}

// ListDeviceCompliance returns every policy result for one device, for the
// device detail page.
func (q *Queries) ListDeviceCompliance(ctx context.Context, deviceID uuid.UUID) ([]DeviceCompliance, error) {
	rows, err := q.db.Query(ctx, `
		SELECT device_id, policy_id, state, failures, evaluated_at
		FROM device_compliance
		WHERE tenant_id = $1 AND device_id = $2
		ORDER BY policy_id`, DefaultTenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCompliance
	for rows.Next() {
		var dc DeviceCompliance
		if err := rows.Scan(&dc.DeviceID, &dc.PolicyID, &dc.State, &dc.Failures, &dc.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

// ListPolicyCompliance returns one page of device results for a policy,
// optionally narrowed to a single state, for the policy's device list.
func (q *Queries) ListPolicyCompliance(ctx context.Context, policyID uuid.UUID, state string, page Page) ([]DeviceCompliance, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT dc.device_id, dc.policy_id, d.hostname, dc.state, dc.failures, dc.evaluated_at,
		       count(*) OVER () AS total
		FROM device_compliance dc
		JOIN devices d ON d.id = dc.device_id
		WHERE dc.tenant_id = $1 AND dc.policy_id = $2
		  AND ($3 = '' OR dc.state = $3)
		ORDER BY lower(d.hostname)
		LIMIT $4 OFFSET $5`, DefaultTenantID, policyID, state, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []DeviceCompliance
	total := 0
	for rows.Next() {
		var dc DeviceCompliance
		if err := rows.Scan(&dc.DeviceID, &dc.PolicyID, &dc.Hostname, &dc.State, &dc.Failures, &dc.EvaluatedAt, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, dc)
	}
	return out, total, rows.Err()
}

// ComplianceOverall derives each device's overall state (design §2): the
// worst state across its rows, or not_evaluated if it has none.
func (q *Queries) ComplianceOverall(ctx context.Context, deviceIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(deviceIDs))
	for _, id := range deviceIDs {
		out[id] = ComplianceNotEvaluated
	}
	if len(deviceIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.Query(ctx, `
		SELECT device_id, state FROM device_compliance
		WHERE tenant_id = $1 AND device_id = ANY($2)`, DefaultTenantID, deviceIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, err
		}
		if cur := out[id]; cur == ComplianceNotEvaluated || complianceRank[state] > complianceRank[cur] {
			out[id] = state
		}
	}
	return out, rows.Err()
}

// ComplianceCounts returns the overall-state counts (including not_evaluated)
// across active devices, for the dashboard's compliance bar. "Active" mirrors
// the console's device list and FleetBar: status = 'active' in the devices
// table (a device is still active while merely stale, i.e. overdue to check
// in; retired and replaced devices are excluded).
func (q *Queries) ComplianceCounts(ctx context.Context) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT d.id, dc.state
		FROM devices d
		LEFT JOIN device_compliance dc ON dc.device_id = d.id AND dc.tenant_id = d.tenant_id
		WHERE d.tenant_id = $1 AND d.status = $2`, DefaultTenantID, DeviceActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	overall := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var state *string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, err
		}
		cur, ok := overall[id]
		if !ok {
			cur = ComplianceNotEvaluated
			overall[id] = cur
		}
		if state == nil {
			continue
		}
		if cur == ComplianceNotEvaluated || complianceRank[*state] > complianceRank[cur] {
			overall[id] = *state
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	counts := map[string]int{
		ComplianceCompliant:    0,
		ComplianceNonCompliant: 0,
		ComplianceUnknown:      0,
		ComplianceNotEvaluated: 0,
	}
	for _, s := range overall {
		counts[s]++
	}
	return counts, nil
}
