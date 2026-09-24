package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/alerts"
	"retune/internal/server/store"
)

// deliveryHistory is how many past attempts the console shows. It is a
// diagnostic - "did my alert go out" - not a log to page through.
const deliveryHistory = 50

type channelJSON struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	HasSecret bool            `json:"has_secret"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	CreatedBy string          `json:"created_by"`
}

// newChannelJSON never serialises the secret itself - only whether one is
// set. A shared signing key that the console can read back is a key that
// every read-only account has. For the same reason a read-only caller sees a
// webhook's scheme and host but not its path: for Slack, Teams and many other
// receivers the URL is the credential, and anyone holding it can post into
// the channel.
func newChannelJSON(c store.NotificationChannel, full bool) channelJSON {
	config := json.RawMessage(c.Config)
	if !full && c.Kind == store.ChannelWebhook {
		config = redactWebhook(c.Config)
	}
	return channelJSON{
		ID: c.ID.String(), Name: c.Name, Kind: c.Kind, Config: config,
		Enabled: c.Enabled, HasSecret: len(c.SecretCiphertext) > 0,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, CreatedBy: c.CreatedBy,
	}
}

// redactWebhook replaces a webhook config's URL with its scheme and host.
func redactWebhook(raw []byte) json.RawMessage {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return json.RawMessage(`{}`)
	}
	if s, ok := cfg["url"].(string); ok {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			cfg["url"] = u.Scheme + "://" + u.Host + "/…"
		} else {
			cfg["url"] = "…"
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

type channelRequest struct {
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled"`
	// Secret is write-only. Absent leaves the stored one alone; empty clears
	// it; anything else replaces it.
	Secret *string `json:"secret"`
}

type alertRuleJSON struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Params      json.RawMessage `json:"params"`
	Description string          `json:"description"`
	ChannelID   string          `json:"channel_id"`
	ChannelName string          `json:"channel_name"`
	ChannelKind string          `json:"channel_kind"`
	Enabled     bool            `json:"enabled"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by"`
}

func newAlertRuleJSON(r store.AlertRule) alertRuleJSON {
	out := alertRuleJSON{
		ID: r.ID.String(), Name: r.Name, Kind: r.Kind, Params: json.RawMessage(r.Params),
		ChannelID: r.ChannelID.String(), ChannelName: r.ChannelName, ChannelKind: r.ChannelKind,
		Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, CreatedBy: r.CreatedBy,
	}
	// The sentence the console shows comes from the same function the alert
	// message uses, so a rule never reads one way in the list and another in
	// the email it sends.
	if params, err := alerts.ParseParams(r.Kind, r.Params); err == nil {
		out.Description = alerts.Describe(r.Kind, params)
	}
	return out
}

type alertRuleRequest struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params"`
	ChannelID string          `json:"channel_id"`
	Enabled   *bool           `json:"enabled"`
}

type firingAlertJSON struct {
	RuleID      string     `json:"rule_id"`
	RuleName    string     `json:"rule_name"`
	RuleKind    string     `json:"rule_kind"`
	SubjectKey  string     `json:"subject_key"`
	Subject     string     `json:"subject"`
	FiringSince time.Time  `json:"firing_since"`
	NotifiedAt  *time.Time `json:"notified_at"`
}

type deliveryJSON struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	ChannelName string    `json:"channel_name"`
	At          time.Time `json:"at"`
	OK          bool      `json:"ok"`
	Detail      string    `json:"detail"`
	Firing      int       `json:"firing"`
	Resolved    int       `json:"resolved"`
}

// writeAlertError maps the two "you can fix this" errors onto 400 and leaves
// everything else as a 500, the same split writeComplianceError makes.
func (h *Handler) writeAlertError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such "+what)
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "name_taken", "that name is already taken")
	case errors.Is(err, store.ErrInUse):
		writeError(w, http.StatusConflict, "in_use",
			"an alert rule still delivers to this channel; delete the rule first")
	case errors.Is(err, alerts.ErrBadRule), errors.Is(err, alerts.ErrBadChannel), errors.Is(err, alerts.ErrNoSMTP):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

func (h *Handler) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListNotificationChannels(r.Context())
	if err != nil {
		h.internal(w, "list notification channels", err)
		return
	}
	items := make([]channelJSON, 0, len(rows))
	for _, c := range rows {
		items = append(items, newChannelJSON(c, caller(r).Admin.Role == store.RoleAdmin))
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

func (h *Handler) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if !decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "a channel needs a name")
		return
	}
	cfg, err := h.validChannelConfig(req.Kind, req.Config)
	if err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		h.internal(w, "new channel id", err)
		return
	}
	ch := store.NotificationChannel{
		ID: id, Name: name, Kind: req.Kind, Config: cfg, Enabled: true,
		CreatedAt: h.Now(), UpdatedAt: h.Now(), CreatedBy: caller(r).Admin.Email,
	}
	if req.Enabled != nil {
		ch.Enabled = *req.Enabled
	}
	if req.Secret != nil && *req.Secret != "" {
		if ch.SecretCiphertext, ch.SecretNonce, err = h.Alerts.SealSecret(id, *req.Secret); err != nil {
			h.internal(w, "seal channel secret", err)
			return
		}
	}
	ctx := r.Context()
	if err := h.Store.Q().CreateNotificationChannel(ctx, ch); err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	h.auditAlert(ctx, ch.CreatedBy, "notification_channel.created", "notification_channel", ch.ID,
		map[string]any{"name": ch.Name, "kind": ch.Kind})
	writeJSON(w, http.StatusCreated, newChannelJSON(ch, true))
}

func (h *Handler) getNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such notification channel")
	if !ok {
		return
	}
	ch, err := h.Store.Q().GetNotificationChannel(r.Context(), store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	writeJSON(w, http.StatusOK, newChannelJSON(ch, caller(r).Admin.Role == store.RoleAdmin))
}

func (h *Handler) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such notification channel")
	if !ok {
		return
	}
	var req channelRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	ch, err := h.Store.Q().GetNotificationChannel(ctx, store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	// A channel's kind is fixed: an email channel that became a webhook would
	// keep a recipient list nobody reads and lose the address that was
	// reviewed when it was created.
	if req.Kind != "" && req.Kind != ch.Kind {
		writeError(w, http.StatusBadRequest, "bad_request", "a channel's kind cannot be changed")
		return
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		ch.Name = name
	}
	if len(req.Config) > 0 {
		if ch.Config, err = h.validChannelConfig(ch.Kind, req.Config); err != nil {
			h.writeAlertError(w, "notification channel", err)
			return
		}
	}
	if req.Enabled != nil {
		ch.Enabled = *req.Enabled
	}
	if req.Secret != nil {
		if ch.SecretCiphertext, ch.SecretNonce, err = h.Alerts.SealSecret(id, *req.Secret); err != nil {
			h.internal(w, "seal channel secret", err)
			return
		}
	}
	ch.UpdatedAt = h.Now()
	if err := h.Store.Q().UpdateNotificationChannel(ctx, store.DefaultTenantID, ch); err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	h.auditAlert(ctx, caller(r).Admin.Email, "notification_channel.updated", "notification_channel", ch.ID,
		map[string]any{"name": ch.Name, "enabled": ch.Enabled})
	writeJSON(w, http.StatusOK, newChannelJSON(ch, caller(r).Admin.Role == store.RoleAdmin))
}

func (h *Handler) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such notification channel")
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.Store.Q().DeleteNotificationChannel(ctx, store.DefaultTenantID, id); err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	h.auditAlert(ctx, caller(r).Admin.Email, "notification_channel.deleted", "notification_channel", id, nil)
	writeNoContent(w)
}

// testNotificationChannel sends a fixed message so a wrong relay or a typo'd
// URL is found while somebody is looking at the form. It is a write because
// it makes the server talk to the outside world on request.
func (h *Handler) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such notification channel")
	if !ok {
		return
	}
	ctx := r.Context()
	ch, err := h.Store.Q().GetNotificationChannel(ctx, store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "notification channel", err)
		return
	}
	actor := caller(r).Admin.Email
	sendErr := h.Alerts.Test(ctx, ch)
	h.auditAlert(ctx, actor, "notification_channel.tested", "notification_channel", ch.ID,
		map[string]any{"ok": sendErr == nil})
	if sendErr != nil {
		// The relay's own words, because "it did not work" is not something
		// an administrator can act on.
		writeError(w, http.StatusBadGateway, "delivery_failed", sendErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, channelTest{OK: true})
}

// validChannelConfig parses a channel's configuration and, for email, refuses
// one this deployment could never deliver.
func (h *Handler) validChannelConfig(kind string, raw json.RawMessage) (json.RawMessage, error) {
	cfg, err := alerts.ParseChannelConfig(kind, raw)
	if err != nil {
		return nil, err
	}
	if kind == store.ChannelEmail && !h.Alerts.SMTP.Configured() {
		return nil, alerts.ErrNoSMTP
	}
	// Re-encoded from the parsed value, so what is stored is the normalised
	// form that was validated rather than whatever shape it arrived in.
	return json.Marshal(cfg)
}

func (h *Handler) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListAlertRules(r.Context(), false)
	if err != nil {
		h.internal(w, "list alert rules", err)
		return
	}
	items := make([]alertRuleJSON, 0, len(rows))
	for _, rule := range rows {
		items = append(items, newAlertRuleJSON(rule))
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

func (h *Handler) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var req alertRuleRequest
	if !decode(w, r, &req) {
		return
	}
	rule, err := h.alertRuleFrom(r.Context(), req, store.AlertRule{
		CreatedAt: h.Now(), CreatedBy: caller(r).Admin.Email, Enabled: true,
	})
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	if rule.ID, err = uuid.NewV7(); err != nil {
		h.internal(w, "new rule id", err)
		return
	}
	ctx := r.Context()
	if err := h.Store.Q().CreateAlertRule(ctx, rule); err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	h.auditAlert(ctx, rule.CreatedBy, "alert_rule.created", "alert_rule", rule.ID,
		map[string]any{"name": rule.Name, "kind": rule.Kind})
	// Read it back so the response carries the channel's name, which the
	// listing joins in and the insert does not.
	stored, err := h.Store.Q().GetAlertRule(ctx, store.DefaultTenantID, rule.ID)
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	writeJSON(w, http.StatusCreated, newAlertRuleJSON(stored))
}

func (h *Handler) getAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such alert rule")
	if !ok {
		return
	}
	rule, err := h.Store.Q().GetAlertRule(r.Context(), store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	writeJSON(w, http.StatusOK, newAlertRuleJSON(rule))
}

func (h *Handler) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such alert rule")
	if !ok {
		return
	}
	var req alertRuleRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	existing, err := h.Store.Q().GetAlertRule(ctx, store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	rule, err := h.alertRuleFrom(ctx, req, existing)
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	rule.ID = id
	if err := h.Store.Q().UpdateAlertRule(ctx, store.DefaultTenantID, rule); err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	h.auditAlert(ctx, caller(r).Admin.Email, "alert_rule.updated", "alert_rule", id,
		map[string]any{"name": rule.Name, "kind": rule.Kind, "enabled": rule.Enabled})
	stored, err := h.Store.Q().GetAlertRule(ctx, store.DefaultTenantID, id)
	if err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	writeJSON(w, http.StatusOK, newAlertRuleJSON(stored))
}

func (h *Handler) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such alert rule")
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.Store.Q().DeleteAlertRule(ctx, store.DefaultTenantID, id); err != nil {
		h.writeAlertError(w, "alert rule", err)
		return
	}
	h.auditAlert(ctx, caller(r).Admin.Email, "alert_rule.deleted", "alert_rule", id, nil)
	writeNoContent(w)
}

// alertRuleFrom validates a request onto an existing rule (or a blank one for
// a create), so the same parsing covers both and a rule is never stored with
// parameters its kind does not understand.
func (h *Handler) alertRuleFrom(ctx context.Context, req alertRuleRequest, base store.AlertRule) (store.AlertRule, error) {
	rule := base
	if name := strings.TrimSpace(req.Name); name != "" {
		rule.Name = name
	}
	if rule.Name == "" {
		return store.AlertRule{}, fmt.Errorf("%w: a rule needs a name", alerts.ErrBadRule)
	}
	if req.Kind != "" {
		rule.Kind = req.Kind
	}
	if len(req.Params) > 0 {
		rule.Params = []byte(req.Params)
	}
	if len(rule.Params) == 0 {
		rule.Params = []byte("{}")
	}
	params, err := alerts.ParseParams(rule.Kind, rule.Params)
	if err != nil {
		return store.AlertRule{}, err
	}
	// Stored normalised, so a rule's parameters read back the way they were
	// understood rather than the way they were typed.
	if rule.Params, err = marshalParams(rule.Kind, params); err != nil {
		return store.AlertRule{}, err
	}
	if req.ChannelID != "" {
		id, err := uuid.Parse(req.ChannelID)
		if err != nil {
			return store.AlertRule{}, fmt.Errorf("%w: channel_id must be a UUID", alerts.ErrBadRule)
		}
		rule.ChannelID = id
	}
	if rule.ChannelID == (uuid.UUID{}) {
		return store.AlertRule{}, fmt.Errorf("%w: a rule needs a channel to deliver to", alerts.ErrBadRule)
	}
	switch _, err := h.Store.Q().GetNotificationChannel(ctx, store.DefaultTenantID, rule.ChannelID); {
	case errors.Is(err, store.ErrNotFound):
		return store.AlertRule{}, fmt.Errorf("%w: there is no such channel", alerts.ErrBadRule)
	case err != nil:
		return store.AlertRule{}, err
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	rule.UpdatedAt = h.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.UpdatedAt
	}
	return rule, nil
}

func marshalParams(kind string, p alerts.Params) ([]byte, error) {
	out := map[string]any{}
	switch kind {
	case store.AlertDeviceNonCompliant:
		if p.PolicyID != nil {
			out["policy_id"] = p.PolicyID.String()
		}
	case store.AlertDeviceStale:
		out["hours"] = p.Hours
	case store.AlertDeploymentFailed:
		if p.ItemKind != "" {
			out["item_kind"] = p.ItemKind
		}
	}
	return json.Marshal(out)
}

func (h *Handler) listFiringAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListFiringAlerts(r.Context())
	if err != nil {
		h.internal(w, "list firing alerts", err)
		return
	}
	items := make([]firingAlertJSON, 0, len(rows))
	for _, a := range rows {
		items = append(items, firingAlertJSON{
			RuleID: a.RuleID.String(), RuleName: a.RuleName, RuleKind: a.RuleKind,
			SubjectKey: a.SubjectKey, Subject: a.Subject,
			FiringSince: a.FiringSince, NotifiedAt: a.NotifiedAt,
		})
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

func (h *Handler) listAlertDeliveries(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListAlertDeliveries(r.Context(), deliveryHistory)
	if err != nil {
		h.internal(w, "list alert deliveries", err)
		return
	}
	items := make([]deliveryJSON, 0, len(rows))
	for _, d := range rows {
		items = append(items, deliveryJSON{
			ID: d.ID.String(), RuleID: d.RuleID.String(), RuleName: d.RuleName,
			ChannelName: d.ChannelName, At: d.At, OK: d.OK, Detail: d.Detail,
			Firing: d.Firing, Resolved: d.Resolved,
		})
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

// auditAlert records an administrator's change. A failure to write the audit
// row is logged rather than returned: the change has already happened, and
// reporting it as an error would tell the console to show a failure that did
// not occur.
func (h *Handler) auditAlert(ctx context.Context, actor, action, kind string, id uuid.UUID, details map[string]any) {
	err := h.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: action, TargetKind: kind, TargetID: id.String(), Details: details,
	})
	if err != nil {
		h.log().Error("write audit entry", "error", err, "action", action)
	}
}
