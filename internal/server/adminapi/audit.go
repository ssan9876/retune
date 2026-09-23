package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"time"

	"retune/internal/server/store"
)

type auditJSON struct {
	ID         string         `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
	At         time.Time      `json:"at"`
}

// auditFilterFrom reads ?actor=, ?action=, ?since= and ?until= (RFC 3339),
// answering 400 itself for a time it cannot read.
func auditFilterFrom(w http.ResponseWriter, r *http.Request) (store.AuditFilter, bool) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Action: q.Get("action")}
	for _, t := range []struct {
		name string
		dst  *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(t.name); v != "" {
			parsed, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", t.name+" must be an RFC 3339 time, e.g. 2026-09-01T00:00:00Z")
				return f, false
			}
			*t.dst = parsed
		}
	}
	return f, true
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	f, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	page := pageFrom(r)
	f.Page = page
	rows, total, err := h.Store.Q().ListAuditPage(r.Context(), f)
	if err != nil {
		h.internal(w, "list audit log", err)
		return
	}
	items := make([]auditJSON, 0, len(rows))
	for _, e := range rows {
		items = append(items, auditJSON{
			ID: e.ID.String(), Actor: e.Actor, Action: e.Action, TargetKind: e.TargetKind,
			TargetID: e.TargetID, Details: e.Details, At: e.At,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

var auditExportHeader = []string{"at", "actor", "action", "target_kind", "target_id", "details", "id"}

// exportAudit streams the audit log, with the same filters as the listing,
// newest first, a page at a time, so a year of history never sits in memory.
// The details column is the entry's JSON, formula-guarded like every cell.
func (h *Handler) exportAudit(w http.ResponseWriter, r *http.Request) {
	f, ok := auditFilterFrom(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	cw := csv.NewWriter(w)
	if err := cw.Write(auditExportHeader); err != nil {
		return
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return
	}
	for offset := 0; ; {
		f.Page = store.Page{Limit: exportPageSize, Offset: offset}
		rows, total, err := h.Store.Q().ListAuditPage(ctx, f)
		if err != nil {
			h.logExportErr("export audit log", err)
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, e := range rows {
			details, _ := json.Marshal(e.Details)
			if err := csvRow(cw, e.At.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.TargetKind,
				e.TargetID, string(details), e.ID.String()); err != nil {
				return
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return
		}
		offset += len(rows)
		if offset >= total {
			break
		}
	}
}
