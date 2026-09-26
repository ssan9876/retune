package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInUse is returned when a row cannot be deleted because something still
// references it.
var ErrInUse = errors.New("in use")

// Channel kinds and rule kinds. They are also CHECK constraints in the
// schema; these constants are what Go code compares against.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"

	AlertDeviceNonCompliant = "device_non_compliant"
	AlertDeviceStale        = "device_stale"
	AlertDeploymentFailed   = "deployment_failed"
	// AlertAgentRolloutHalted fires while an automatic agent rollout is
	// halted: a pilot device rolled back, or an approval was refused.
	AlertAgentRolloutHalted = "agent_rollout_halted"
)

// NotificationChannel is where an alert is delivered. The secret is a
// webhook's shared signing key, sealed by the caller; the store never sees it
// in the clear and no listing returns it.
type NotificationChannel struct {
	ID               uuid.UUID
	Name             string
	Kind             string
	Config           []byte // raw JSON; parsing lives in internal/server/alerts
	SecretCiphertext []byte
	SecretNonce      []byte
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CreatedBy        string
}

const channelCols = `id, name, kind, config, secret_ciphertext, secret_nonce, enabled, created_at, updated_at, created_by`

func scanChannel(row pgx.Row) (NotificationChannel, error) {
	var c NotificationChannel
	err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.SecretCiphertext, &c.SecretNonce,
		&c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.CreatedBy)
	return c, notFound(err)
}

func (q *Queries) CreateNotificationChannel(ctx context.Context, c NotificationChannel) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO notification_channels
			(id, tenant_id, name, kind, config, secret_ciphertext, secret_nonce, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		c.ID, DefaultTenantID, c.Name, c.Kind, c.Config, c.SecretCiphertext, c.SecretNonce,
		c.Enabled, c.CreatedAt, c.UpdatedAt, c.CreatedBy)
	return duplicate(err)
}

func (q *Queries) GetNotificationChannel(ctx context.Context, tenantID, id uuid.UUID) (NotificationChannel, error) {
	return scanChannel(q.db.QueryRow(ctx,
		`SELECT `+channelCols+` FROM notification_channels WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

// ListNotificationChannels returns every channel, alphabetically. There are a
// handful of these per deployment, so they are not paged.
func (q *Queries) ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	rows, err := q.db.Query(ctx,
		`SELECT `+channelCols+` FROM notification_channels WHERE tenant_id = $1 ORDER BY lower(name)`,
		DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationChannel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateNotificationChannel replaces a channel's editable fields. The secret
// columns are written as given, so a caller that means to keep the existing
// secret passes it back unchanged.
func (q *Queries) UpdateNotificationChannel(ctx context.Context, tenantID uuid.UUID, c NotificationChannel) error {
	_, err := q.db.Exec(ctx, `
		UPDATE notification_channels
		SET name = $3, config = $4, secret_ciphertext = $5, secret_nonce = $6, enabled = $7, updated_at = $8
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, c.ID, c.Name, c.Config, c.SecretCiphertext, c.SecretNonce, c.Enabled, c.UpdatedAt)
	return duplicate(err)
}

// DeleteNotificationChannel removes a channel, or reports ErrInUse if a rule
// still delivers to it. The foreign key is RESTRICT rather than CASCADE
// because silently deleting the rules would silently stop the alerting.
func (q *Queries) DeleteNotificationChannel(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := q.db.Exec(ctx,
		`DELETE FROM notification_channels WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrInUse
	}
	return err
}

// AlertRule is one condition worth telling somebody about.
type AlertRule struct {
	ID        uuid.UUID
	Name      string
	Kind      string
	Params    []byte // raw JSON object; parsing lives in internal/server/alerts
	ChannelID uuid.UUID
	// ChannelName and ChannelKind are filled in by the listing queries, which
	// join, and left empty by the single-row get.
	ChannelName string
	ChannelKind string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   string
}

const alertRuleCols = `r.id, r.name, r.kind, r.params, r.channel_id, r.enabled, r.created_at, r.updated_at, r.created_by`

func scanAlertRule(row pgx.Row) (AlertRule, error) {
	var r AlertRule
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &r.Params, &r.ChannelID, &r.Enabled,
		&r.CreatedAt, &r.UpdatedAt, &r.CreatedBy, &r.ChannelName, &r.ChannelKind)
	return r, notFound(err)
}

func (q *Queries) CreateAlertRule(ctx context.Context, r AlertRule) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO alert_rules (id, tenant_id, name, kind, params, channel_id, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.ID, DefaultTenantID, r.Name, r.Kind, r.Params, r.ChannelID, r.Enabled,
		r.CreatedAt, r.UpdatedAt, r.CreatedBy)
	return duplicate(err)
}

func (q *Queries) GetAlertRule(ctx context.Context, tenantID, id uuid.UUID) (AlertRule, error) {
	return scanAlertRule(q.db.QueryRow(ctx, `
		SELECT `+alertRuleCols+`, c.name, c.kind
		FROM alert_rules r JOIN notification_channels c ON c.id = r.channel_id
		WHERE r.tenant_id = $1 AND r.id = $2`, tenantID, id))
}

// ListAlertRules returns every rule with its channel, alphabetically. enabled
// narrows it to the rules the sweeper should actually evaluate.
func (q *Queries) ListAlertRules(ctx context.Context, enabledOnly bool) ([]AlertRule, error) {
	// A rule whose channel is disabled still evaluates: its state has to keep
	// up with the fleet, or re-enabling the channel would replay a backlog.
	rows, err := q.db.Query(ctx, `
		SELECT `+alertRuleCols+`, c.name, c.kind
		FROM alert_rules r JOIN notification_channels c ON c.id = r.channel_id
		WHERE r.tenant_id = $1 AND (NOT $2 OR r.enabled)
		ORDER BY lower(r.name)`, DefaultTenantID, enabledOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		r, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (q *Queries) UpdateAlertRule(ctx context.Context, tenantID uuid.UUID, r AlertRule) error {
	_, err := q.db.Exec(ctx, `
		UPDATE alert_rules SET name = $3, kind = $4, params = $5, channel_id = $6, enabled = $7, updated_at = $8
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, r.ID, r.Name, r.Kind, r.Params, r.ChannelID, r.Enabled, r.UpdatedAt)
	return duplicate(err)
}

// DeleteAlertRule removes a rule; its state and deliveries cascade, because
// neither means anything without the rule that produced them.
func (q *Queries) DeleteAlertRule(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM alert_rules WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// AlertSubject is one thing a rule is firing about: an opaque key that is
// stable for as long as the problem is the same problem, and a line a person
// can read.
type AlertSubject struct {
	Key     string
	Subject string
}

// FiringAlert is one subject currently firing, with the rule that found it.
type FiringAlert struct {
	RuleID      uuid.UUID
	RuleName    string
	RuleKind    string
	SubjectKey  string
	Subject     string
	FiringSince time.Time
	NotifiedAt  *time.Time
}

// ListAlertState returns everything rule is currently firing about, keyed by
// subject key so the evaluator can diff it against what it just found.
func (q *Queries) ListAlertState(ctx context.Context, ruleID uuid.UUID) (map[string]FiringAlert, error) {
	rows, err := q.db.Query(ctx, `
		SELECT subject_key, subject, firing_since, notified_at FROM alert_state
		WHERE tenant_id = $1 AND rule_id = $2`, DefaultTenantID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FiringAlert{}
	for rows.Next() {
		a := FiringAlert{RuleID: ruleID}
		if err := rows.Scan(&a.SubjectKey, &a.Subject, &a.FiringSince, &a.NotifiedAt); err != nil {
			return nil, err
		}
		out[a.SubjectKey] = a
	}
	return out, rows.Err()
}

// InsertAlertState records that a subject has started firing. The subject
// line is refreshed on conflict - the machine is the same, what is wrong with
// it may have been reworded - but firing_since is not, because that is when
// the problem started and not when it was last looked at.
func (q *Queries) InsertAlertState(ctx context.Context, ruleID uuid.UUID, s AlertSubject, at time.Time) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO alert_state (rule_id, subject_key, tenant_id, subject, firing_since)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (rule_id, subject_key) DO UPDATE SET subject = EXCLUDED.subject`,
		ruleID, s.Key, DefaultTenantID, s.Subject, at)
	return err
}

// DeleteAlertState clears the subjects a rule has stopped firing about.
func (q *Queries) DeleteAlertState(ctx context.Context, ruleID uuid.UUID, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := q.db.Exec(ctx,
		`DELETE FROM alert_state WHERE tenant_id = $1 AND rule_id = $2 AND subject_key = ANY($3)`,
		DefaultTenantID, ruleID, keys)
	return err
}

// MarkAlertsNotified stamps the subjects a delivery actually carried. Until
// this runs they still read as new, which is what makes a failed send retry
// on the next tick rather than being lost.
func (q *Queries) MarkAlertsNotified(ctx context.Context, ruleID uuid.UUID, keys []string, at time.Time) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := q.db.Exec(ctx, `
		UPDATE alert_state SET notified_at = $4
		WHERE tenant_id = $1 AND rule_id = $2 AND subject_key = ANY($3)`,
		DefaultTenantID, ruleID, keys, at)
	return err
}

// ListFiringAlerts returns everything currently firing across every rule,
// longest-running first: the console's "what is wrong right now".
func (q *Queries) ListFiringAlerts(ctx context.Context) ([]FiringAlert, error) {
	rows, err := q.db.Query(ctx, `
		SELECT s.rule_id, r.name, r.kind, s.subject_key, s.subject, s.firing_since, s.notified_at
		FROM alert_state s JOIN alert_rules r ON r.id = s.rule_id
		WHERE s.tenant_id = $1
		ORDER BY s.firing_since, s.subject_key`, DefaultTenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FiringAlert
	for rows.Next() {
		var a FiringAlert
		if err := rows.Scan(&a.RuleID, &a.RuleName, &a.RuleKind, &a.SubjectKey, &a.Subject,
			&a.FiringSince, &a.NotifiedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AlertDelivery is one attempt to tell somebody, kept so that "why did I not
// get an email" has an answer.
type AlertDelivery struct {
	ID          uuid.UUID
	RuleID      uuid.UUID
	RuleName    string
	ChannelName string
	At          time.Time
	OK          bool
	Detail      string
	Firing      int
	Resolved    int
}

func (q *Queries) InsertAlertDelivery(ctx context.Context, d AlertDelivery, channelID uuid.UUID) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `
		INSERT INTO alert_deliveries (id, tenant_id, rule_id, channel_id, at, ok, detail, firing, resolved)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, DefaultTenantID, d.RuleID, channelID, d.At, d.OK, d.Detail, d.Firing, d.Resolved)
	return err
}

// ListAlertDeliveries returns the most recent attempts, newest first.
func (q *Queries) ListAlertDeliveries(ctx context.Context, limit int) ([]AlertDelivery, error) {
	rows, err := q.db.Query(ctx, `
		SELECT d.id, d.rule_id, r.name, c.name, d.at, d.ok, d.detail, d.firing, d.resolved
		FROM alert_deliveries d
		JOIN alert_rules r ON r.id = d.rule_id
		JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.tenant_id = $1
		ORDER BY d.at DESC
		LIMIT $2`, DefaultTenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertDelivery
	for rows.Next() {
		var d AlertDelivery
		if err := rows.Scan(&d.ID, &d.RuleID, &d.RuleName, &d.ChannelName, &d.At, &d.OK,
			&d.Detail, &d.Firing, &d.Resolved); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteOldAlertDeliveries prunes the history the sweeper keeps.
func (q *Queries) DeleteOldAlertDeliveries(ctx context.Context, before time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx,
		`DELETE FROM alert_deliveries WHERE tenant_id = $1 AND at < $2`, DefaultTenantID, before)
	return tag.RowsAffected(), err
}

// The three queries below are the rule kinds themselves: each returns the
// subjects firing right now. They name the thing that is wrong rather than the
// moment it was noticed, because that key is what tells a problem still going
// on from a new one.

// FiringNonCompliantDevices returns active devices failing a compliance
// policy. With a policy id it is that one policy; without, any of them, and
// the subject names which.
func (q *Queries) FiringNonCompliantDevices(ctx context.Context, policyID *uuid.UUID) ([]AlertSubject, error) {
	return q.alertSubjects(ctx, `
		SELECT 'device:' || d.id,
		       d.hostname || ' is non-compliant with ' || string_agg(p.name, ', ' ORDER BY lower(p.name))
		FROM device_compliance dc
		JOIN devices d ON d.id = dc.device_id AND d.tenant_id = dc.tenant_id
		JOIN compliance_policies p ON p.id = dc.policy_id
		WHERE dc.tenant_id = $1 AND d.status = $2 AND dc.state = 'non_compliant'
		  AND ($3::uuid IS NULL OR dc.policy_id = $3)
		GROUP BY d.id, d.hostname
		ORDER BY lower(d.hostname)`, DefaultTenantID, DeviceActive, policyID)
}

// FiringStaleDevices returns active devices that have not checked in since
// cutoff, including those that never have.
func (q *Queries) FiringStaleDevices(ctx context.Context, cutoff time.Time) ([]AlertSubject, error) {
	return q.alertSubjects(ctx, `
		SELECT 'device:' || id,
		       hostname || CASE WHEN last_seen_at IS NULL
		           THEN ' has never checked in'
		           ELSE ' has not checked in since ' ||
		                to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC'
		       END
		FROM devices
		WHERE tenant_id = $1 AND status = $2 AND (last_seen_at IS NULL OR last_seen_at < $3)
		ORDER BY lower(hostname)`, DefaultTenantID, DeviceActive, cutoff)
}

// FiringFailedDeployments returns active devices with a failed item status,
// one subject per failing item rather than per device: two broken scripts on
// one machine are two things to fix.
func (q *Queries) FiringFailedDeployments(ctx context.Context, itemKind string) ([]AlertSubject, error) {
	return q.alertSubjects(ctx, `
		SELECT 'device:' || d.id || '/item:' || s.item_kind || ':' || s.item_id,
		       d.hostname || ': ' || s.item_kind || ' deployment failed' ||
		           CASE WHEN s.detail = '' THEN '' ELSE ' - ' || left(s.detail, 120) END
		FROM device_item_status s
		JOIN devices d ON d.id = s.device_id AND d.tenant_id = s.tenant_id
		WHERE s.tenant_id = $1 AND d.status = $2 AND s.status = 'failed'
		  AND ($3 = '' OR s.item_kind = $3)
		ORDER BY lower(d.hostname), s.item_kind, s.item_id`, DefaultTenantID, DeviceActive, itemKind)
}

func (q *Queries) alertSubjects(ctx context.Context, sql string, args ...any) ([]AlertSubject, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertSubject
	for rows.Next() {
		var s AlertSubject
		if err := rows.Scan(&s.Key, &s.Subject); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// duplicate maps a unique-violation into ErrDuplicate, which the admin API
// turns into a 409 rather than a 500.
func duplicate(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}
