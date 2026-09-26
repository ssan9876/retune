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
	// Hostname and PolicyName are filled in by the listing queries only, each
	// by the one whose page needs it, not by UpsertDeviceCompliance.
	Hostname    string
	PolicyName  string
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
		DELETE FROM device_compliance WHERE tenant_id = $1 AND device_id = $2 AND NOT (policy_id = ANY($3))`,
		DefaultTenantID, deviceID, keep)
	return err
}

// DeleteComplianceForPolicy removes every device's result for one policy,
// used when a policy is deleted outright (in the same transaction as the
// policy row and its mirrored item-status rows).
func (q *Queries) DeleteComplianceForPolicy(ctx context.Context, policyID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM device_compliance WHERE tenant_id = $1 AND policy_id = $2`, DefaultTenantID, policyID)
	return err
}

// ListDeviceCompliance returns every policy result for one device, for the
// device detail page. It carries each policy's name and orders by it, the
// mirror of ListPolicyCompliance joining devices for the hostname: a page
// that lists policies should read in the order a person would look for them,
// and should not have to fetch the whole policy library to caption a row.
func (q *Queries) ListDeviceCompliance(ctx context.Context, deviceID uuid.UUID) ([]DeviceCompliance, error) {
	rows, err := q.db.Query(ctx, `
		SELECT dc.device_id, dc.policy_id, p.name, dc.state, dc.failures, dc.evaluated_at
		FROM device_compliance dc
		JOIN compliance_policies p ON p.id = dc.policy_id
		WHERE dc.tenant_id = $1 AND dc.device_id = $2
		ORDER BY lower(p.name), dc.policy_id`, DefaultTenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCompliance
	for rows.Next() {
		var dc DeviceCompliance
		if err := rows.Scan(&dc.DeviceID, &dc.PolicyID, &dc.PolicyName, &dc.State, &dc.Failures, &dc.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

// ListPolicyCompliance returns one page of device results for a policy,
// optionally narrowed to a single state, for the policy's device list.
func (q *Queries) ListPolicyCompliance(ctx context.Context, policyID uuid.UUID, state string, page Page, scope DeviceScope) ([]DeviceCompliance, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT dc.device_id, dc.policy_id, d.hostname, dc.state, dc.failures, dc.evaluated_at,
		       count(*) OVER () AS total
		FROM device_compliance dc
		JOIN devices d ON d.id = dc.device_id
		WHERE dc.tenant_id = $1 AND dc.policy_id = $2
		  AND ($3 = '' OR dc.state = $3) AND `+scopeSQL("dc.device_id", 6)+`
		ORDER BY lower(d.hostname), dc.device_id
		LIMIT $4 OFFSET $5`, DefaultTenantID, policyID, state, p.Limit, p.Offset, scope.arg())
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

// PolicyStateCounts returns each of the given policies' device_compliance
// counts by state (compliant, non_compliant, unknown), for the console's
// policy list rollup column. Unlike ComplianceOverall, this counts each
// policy's own rows rather than deriving one worst-state-wins verdict per
// device, so an administrator can see how a policy itself is doing without a
// separate request per row. A policy with no results yet - never evaluated,
// or every device it once applied to has since been unassigned - comes back
// with all three states at zero rather than being absent from the map, so a
// caller never has to tell "zero" apart from "missing" for a real policy id.
func (q *Queries) PolicyStateCounts(ctx context.Context, policyIDs []uuid.UUID, scope DeviceScope) (map[uuid.UUID]map[string]int, error) {
	out := make(map[uuid.UUID]map[string]int, len(policyIDs))
	for _, id := range policyIDs {
		out[id] = map[string]int{
			ComplianceCompliant:    0,
			ComplianceNonCompliant: 0,
			ComplianceUnknown:      0,
		}
	}
	if len(policyIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.Query(ctx, `
		SELECT policy_id, state, count(*)
		FROM device_compliance
		WHERE tenant_id = $1 AND policy_id = ANY($2) AND `+scopeSQL("device_id", 3)+`
		GROUP BY policy_id, state`, DefaultTenantID, policyIDs, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var state string
		var n int
		if err := rows.Scan(&id, &state, &n); err != nil {
			return nil, err
		}
		if _, ok := out[id]; !ok {
			// Defensive: policyIDs is the caller's own list, so every row's
			// policy_id should already be a key, but a stale caller-side
			// cache should not panic on a map write it didn't expect.
			out[id] = map[string]int{}
		}
		out[id][state] = n
	}
	return out, rows.Err()
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
func (q *Queries) ComplianceCounts(ctx context.Context, scope DeviceScope) (map[string]int, error) {
	// The rollup happens in SQL rather than in Go, the same way
	// DeviceBucketCounts computes the bar beside this one: pulling a row per
	// (device x policy) back to derive one verdict each is 100k rows on a
	// 20k-device fleet with five policies, every time the dashboard loads.
	// The inner CASE ladder is complianceRank written as SQL and the outer one
	// its inverse, so worst-state-wins agrees with ComplianceOverall exactly;
	// the device_compliance CHECK constraint is what keeps the three states
	// exhaustive. max() over a device with no rows is NULL, which is the
	// not_evaluated the LEFT JOIN exists to produce.
	rows, err := q.db.Query(ctx, `
		SELECT overall, count(*) FROM (
			SELECT CASE max(CASE dc.state
					WHEN 'compliant' THEN 0
					WHEN 'unknown' THEN 1
					WHEN 'non_compliant' THEN 2
				END)
				WHEN 0 THEN 'compliant'
				WHEN 1 THEN 'unknown'
				WHEN 2 THEN 'non_compliant'
				ELSE 'not_evaluated'
			END AS overall
			FROM devices d
			LEFT JOIN device_compliance dc ON dc.device_id = d.id AND dc.tenant_id = d.tenant_id
			WHERE d.tenant_id = $1 AND d.status = $2 AND `+scopeSQL("d.id", 3)+`
			GROUP BY d.id
		) per_device
		GROUP BY overall`, DefaultTenantID, DeviceActive, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{
		ComplianceCompliant:    0,
		ComplianceNonCompliant: 0,
		ComplianceUnknown:      0,
		ComplianceNotEvaluated: 0,
	}
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		counts[state] = n
	}
	return counts, rows.Err()
}
