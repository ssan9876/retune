package adminapi

import (
	"net/http"
	"time"
)

type auditJSON struct {
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
	At         time.Time      `json:"at"`
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListAuditPage(r.Context(), page)
	if err != nil {
		h.internal(w, "list audit log", err)
		return
	}
	items := make([]auditJSON, 0, len(rows))
	for _, e := range rows {
		items = append(items, auditJSON{
			Actor: e.Actor, Action: e.Action, TargetKind: e.TargetKind,
			TargetID: e.TargetID, Details: e.Details, At: e.At,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}
