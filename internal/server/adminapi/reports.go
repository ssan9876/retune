package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/alerts"
	"retune/internal/server/reports"
	"retune/internal/server/store"
)

// maxReportRecipients bounds who one report goes to.
const maxReportRecipients = 20

type reportJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	PolicyID   string     `json:"policy_id,omitempty"`
	State      string     `json:"state,omitempty"`
	Recipients []string   `json:"recipients"`
	Frequency  string     `json:"frequency"`
	Weekday    int        `json:"weekday"`
	Hour       int        `json:"hour"`
	Timezone   string     `json:"timezone"`
	Enabled    bool       `json:"enabled"`
	NextRunAt  time.Time  `json:"next_run_at"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
}

func newReportJSON(r store.ScheduledReport) reportJSON {
	out := reportJSON{
		ID: r.ID.String(), Name: r.Name, Kind: r.Kind, State: r.State, Recipients: r.Recipients,
		Frequency: r.Frequency, Weekday: r.Weekday, Hour: r.Hour, Timezone: r.Timezone, Enabled: r.Enabled,
		NextRunAt: r.NextRunAt, LastSentAt: r.LastSentAt, LastError: r.LastError,
		CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
	}
	if r.PolicyID != nil {
		out.PolicyID = r.PolicyID.String()
	}
	if out.Recipients == nil {
		out.Recipients = []string{}
	}
	return out
}

type reportRequest struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	PolicyID   string   `json:"policy_id"`
	State      string   `json:"state"`
	Recipients []string `json:"recipients"`
	Frequency  string   `json:"frequency"`
	Weekday    int      `json:"weekday"`
	Hour       int      `json:"hour"`
	Timezone   string   `json:"timezone"`
	Enabled    *bool    `json:"enabled"`
}

// reportFromRequest checks a request and fills in r from it, with its next
// run worked out from now.
func (h *Handler) reportFromRequest(r *http.Request, req reportRequest, into *store.ScheduledReport) error {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return errors.New("name is required, at most 200 characters")
	}
	into.Name = name
	into.Kind, into.State, into.PolicyID = req.Kind, "", nil
	switch req.Kind {
	case store.ReportDevices:
		if req.PolicyID != "" || req.State != "" {
			return errors.New("policy_id and state apply only to a compliance report")
		}
	case store.ReportCompliance:
		id, err := uuid.Parse(req.PolicyID)
		if err != nil {
			return errors.New("a compliance report needs the policy_id of a compliance policy")
		}
		if _, err := h.Store.Q().GetCompliancePolicy(r.Context(), store.DefaultTenantID, id); err != nil {
			return errors.New("there is no compliance policy with that policy_id")
		}
		switch req.State {
		case "", "compliant", "non_compliant", "unknown":
		default:
			return errors.New("state must be compliant, non_compliant or unknown, or empty for every device")
		}
		into.PolicyID, into.State = &id, req.State
	default:
		return errors.New("kind must be devices or compliance")
	}
	if len(req.Recipients) == 0 || len(req.Recipients) > maxReportRecipients {
		return fmt.Errorf("recipients must name 1 to %d email addresses", maxReportRecipients)
	}
	into.Recipients = make([]string, 0, len(req.Recipients))
	for _, addr := range req.Recipients {
		parsed, err := mail.ParseAddress(strings.TrimSpace(addr))
		if err != nil {
			return fmt.Errorf("%q is not an email address", addr)
		}
		into.Recipients = append(into.Recipients, parsed.Address)
	}
	tz := strings.TrimSpace(req.Timezone)
	if tz == "" {
		tz = "UTC"
	}
	sched := reports.Schedule{Frequency: req.Frequency, Weekday: req.Weekday, Hour: req.Hour, Timezone: tz}
	if err := sched.Validate(); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), reports.ErrBadSchedule.Error()+": "))
	}
	next, err := sched.Next(h.Now())
	if err != nil {
		return err
	}
	into.Frequency, into.Weekday, into.Hour, into.Timezone, into.NextRunAt = sched.Frequency, sched.Weekday, sched.Hour, tz, next
	into.Enabled = req.Enabled == nil || *req.Enabled
	if !h.Alerts.SMTPConfigured() {
		return alerts.ErrNoSMTP
	}
	return nil
}

func (h *Handler) listReports(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListReports(r.Context())
	if err != nil {
		h.internal(w, "list reports", err)
		return
	}
	items := make([]reportJSON, 0, len(rows))
	for _, row := range rows {
		items = append(items, newReportJSON(row))
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

func (h *Handler) getReport(w http.ResponseWriter, r *http.Request) {
	row, ok := h.reportFromPath(w, r)
	if ok {
		writeJSON(w, http.StatusOK, newReportJSON(row))
	}
}

func (h *Handler) reportFromPath(w http.ResponseWriter, r *http.Request) (store.ScheduledReport, bool) {
	id, ok := pathUUID(w, r, "no such report")
	if !ok {
		return store.ScheduledReport{}, false
	}
	row, err := h.Store.Q().GetReport(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such report")
		return store.ScheduledReport{}, false
	} else if err != nil {
		h.internal(w, "get report", err)
		return store.ScheduledReport{}, false
	}
	return row, true
}

func (h *Handler) createReport(w http.ResponseWriter, r *http.Request) {
	var req reportRequest
	if !decode(w, r, &req) {
		return
	}
	now := h.Now()
	row := store.ScheduledReport{ID: uuid.Must(uuid.NewV7()), CreatedAt: now, UpdatedAt: now, CreatedBy: caller(r).Admin.Email}
	if err := h.reportFromRequest(r, req, &row); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateReport(ctx, row); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: row.CreatedBy, Action: "report.created", TargetKind: "report", TargetID: row.ID.String(),
			Details: map[string]any{"name": row.Name, "kind": row.Kind, "recipients": row.Recipients},
		})
	})
	h.writeReportResult(w, http.StatusCreated, row, err)
}

func (h *Handler) updateReport(w http.ResponseWriter, r *http.Request) {
	row, ok := h.reportFromPath(w, r)
	if !ok {
		return
	}
	var req reportRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.reportFromRequest(r, req, &row); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	row.UpdatedAt = h.Now()
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpdateReport(ctx, row); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "report.updated", TargetKind: "report", TargetID: row.ID.String(),
			Details: map[string]any{"name": row.Name, "kind": row.Kind, "recipients": row.Recipients, "enabled": row.Enabled},
		})
	})
	h.writeReportResult(w, http.StatusOK, row, err)
}

func (h *Handler) writeReportResult(w http.ResponseWriter, status int, row store.ScheduledReport, err error) {
	switch {
	case err == nil:
		writeJSON(w, status, newReportJSON(row))
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "duplicate", "a report with that name already exists")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such report")
	default:
		h.internal(w, "save report", err)
	}
}

func (h *Handler) deleteReport(w http.ResponseWriter, r *http.Request) {
	row, ok := h.reportFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.DeleteReport(ctx, row.ID); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "report.deleted", TargetKind: "report", TargetID: row.ID.String(),
			Details: map[string]any{"name": row.Name},
		})
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.internal(w, "delete report", err)
		return
	}
	writeNoContent(w)
}

// sendReport sends a report now, off its schedule: to check it arrives.
func (h *Handler) sendReport(w http.ResponseWriter, r *http.Request) {
	row, ok := h.reportFromPath(w, r)
	if !ok {
		return
	}
	if err := h.Reports.SendNow(r.Context(), row); err != nil {
		writeError(w, http.StatusBadGateway, "send_failed", "the report could not be sent: "+err.Error())
		return
	}
	_ = h.Store.Q().InsertAudit(r.Context(), store.AuditEntry{
		Actor: caller(r).Admin.Email, Action: "report.sent", TargetKind: "report", TargetID: row.ID.String(),
		Details: map[string]any{"name": row.Name, "recipients": row.Recipients},
	})
	row, _ = h.Store.Q().GetReport(r.Context(), row.ID)
	writeJSON(w, http.StatusOK, newReportJSON(row))
}
