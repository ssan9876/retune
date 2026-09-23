package adminapi

import (
	"encoding/csv"
	"net/http"

	"retune/internal/server/csvexport"
	"retune/internal/server/store"
)

// exportPageSize is how many rows each export query pulls at a time:
// store.MaxPageLimit, which the list queries clamp to anyway.
const exportPageSize = store.MaxPageLimit

// csvSafe and csvRow are csvexport's, for the exports written here (the
// audit log).
func csvSafe(s string) string { return csvexport.Safe(s) }

func csvRow(w *csv.Writer, cells ...string) error { return csvexport.Row(w, cells...) }

// logExportErr records a failure that happens after the CSV header is
// already on the wire. By that point the status line is committed and the
// body is mid-stream, so there is no clean HTTP error to send back - writing
// a JSON error body here would just corrupt the CSV the client is reading.
// Logging and closing the connection (by returning) is the honest option:
// the client sees a truncated download rather than a row of garbage.
func (h *Handler) logExportErr(msg string, err error) {
	h.log().Error(msg, "error", err)
}

// exportDevices streams every device the caller can see as CSV.
func (h *Handler) exportDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="devices.csv"`)
	if err := csvexport.WriteDevices(r.Context(), h.Store.Q(), caller(r).Scope, w); err != nil {
		h.logExportErr("export devices", err)
	}
}

// exportPolicyDevices streams one policy's device results as CSV, the same
// rows listPolicyDevices pages through as JSON.
func (h *Handler) exportPolicyDevices(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := h.Compliance.Get(ctx, id); err != nil {
		h.writeComplianceError(w, "get compliance policy", err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="compliance-`+id.String()+`.csv"`)
	if err := csvexport.WritePolicyDevices(ctx, h.Store.Q(), id, r.URL.Query().Get("state"), caller(r).Scope, w); err != nil {
		h.logExportErr("export policy devices", err)
	}
}
