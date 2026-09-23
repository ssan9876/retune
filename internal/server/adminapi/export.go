package adminapi

import (
	"encoding/csv"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// exportPageSize bounds how many rows each export query pulls at a time, so
// a fleet of any size streams through constant memory instead of building one
// giant slice before the first byte reaches the client. It is store.MaxPageLimit
// itself: both ListDevicesPage and ListPolicyCompliance clamp to that ceiling
// via Page.Normalized regardless of what's asked for, so anything higher than
// 200 here would be silently ignored - this just says so rather than lying
// about the real page size.
const exportPageSize = store.MaxPageLimit

// csvInjectionPrefixes are the leading characters a spreadsheet treats as
// the start of a formula (or, for tab/CR, as a way to smuggle extra cells or
// rows past a naive importer). A cell starting with one of these gets a
// leading apostrophe, which every spreadsheet reads as "this is text."
const csvInjectionPrefixes = "=+-@\t\r"

// csvSafe defuses formula injection (spec §5) without touching cells that
// don't need it, so an ordinary hostname round-trips unchanged.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(csvInjectionPrefixes, s[0]) >= 0 {
		return "'" + s
	}
	return s
}

// formatTime renders a timestamp the way the export's plain-text cells need
// it; a nil pointer (a device that has never checked in) is an empty cell
// rather than the zero time, which would read as a bogus 0001-01-01 date.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// csvRow writes one record through csvSafe on every cell, so no caller can
// forget to sanitize a column.
func csvRow(w *csv.Writer, cells ...string) error {
	safe := make([]string, len(cells))
	for i, c := range cells {
		safe[i] = csvSafe(c)
	}
	return w.Write(safe)
}

// logExportErr records a failure that happens after the CSV header is
// already on the wire. By that point the status line is committed and the
// body is mid-stream, so there is no clean HTTP error to send back - writing
// a JSON error body here would just corrupt the CSV the client is reading.
// Logging and closing the connection (by returning) is the honest option:
// the client sees a truncated download rather than a row of garbage.
func (h *Handler) logExportErr(msg string, err error) {
	h.log().Error(msg, "error", err)
}

var deviceExportHeader = []string{
	"hostname", "serial", "manufacturer", "model", "os_version", "os_build",
	"agent_version", "status", "compliance", "last_seen_at", "enrolled_at",
}

// exportDevices streams every device as CSV (spec §5): hostname, serial,
// manufacturer, model, os_version, os_build, agent_version, status,
// compliance, last_seen_at, enrolled_at. It pages through the fleet rather
// than loading it all at once, and flushes after each page so a large export
// is visibly progressing rather than sitting silent until the last row.
func (h *Handler) exportDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="devices.csv"`)

	cw := csv.NewWriter(w)
	if err := cw.Write(deviceExportHeader); err != nil {
		// The client went away before the header even landed; nothing left to do.
		return
	}
	// Flush unconditionally: csv.Writer buffers internally, and a zero-device
	// tenant never enters the loop below, so without this the header row
	// would sit in the buffer forever and the response would come back empty.
	cw.Flush()
	if err := cw.Error(); err != nil {
		return
	}

	offset := 0
	for {
		rows, total, err := h.Store.Q().ListDevicesPage(ctx, store.DeviceFilter{
			Page: store.Page{Limit: exportPageSize, Offset: offset}, Scope: caller(r).Scope,
		})
		if err != nil {
			h.logExportErr("export devices", err)
			return
		}
		if len(rows) == 0 {
			break
		}
		ids := make([]uuid.UUID, len(rows))
		for i, d := range rows {
			ids[i] = d.ID
		}
		overall, err := h.Store.Q().ComplianceOverall(ctx, ids)
		if err != nil {
			h.logExportErr("export devices compliance overall", err)
			return
		}
		for _, d := range rows {
			if err := csvRow(cw,
				d.Hostname, d.Serial, d.Manufacturer, d.Model, d.OSVersion, d.OSBuild,
				d.AgentVersion, d.Status, overall[d.ID], formatTime(d.LastSeenAt), formatTime(&d.EnrolledAt),
			); err != nil {
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

var policyDeviceExportHeader = []string{"hostname", "state", "failures", "evaluated_at"}

// exportPolicyDevices streams one policy's device results as CSV (spec §5),
// the same rows listPolicyDevices paginates as JSON: hostname, state,
// failures, evaluated_at. Failures collapse to one cell, semicolon-joined
// details, the same shape mirrorItemStatus already writes into
// device_item_status, so the reason a device failed reads the same way
// wherever an admin sees it.
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
	state := r.URL.Query().Get("state")

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="compliance-`+id.String()+`.csv"`)

	cw := csv.NewWriter(w)
	if err := cw.Write(policyDeviceExportHeader); err != nil {
		return
	}
	// Flush unconditionally: a policy with zero compliance results never
	// enters the loop below, so without this the header row would never
	// leave csv.Writer's internal buffer.
	cw.Flush()
	if err := cw.Error(); err != nil {
		return
	}

	offset := 0
	for {
		rows, total, err := h.Store.Q().ListPolicyCompliance(ctx, id, state, store.Page{Limit: exportPageSize, Offset: offset}, caller(r).Scope)
		if err != nil {
			h.logExportErr("export policy devices", err)
			return
		}
		if len(rows) == 0 {
			break
		}
		for _, dc := range rows {
			failures, err := decodeFailures(dc.Failures)
			if err != nil {
				h.logExportErr("export policy devices decode failures", err)
				return
			}
			details := make([]string, 0, len(failures))
			for _, f := range failures {
				details = append(details, f.Detail)
			}
			if err := csvRow(cw, dc.Hostname, dc.State, strings.Join(details, "; "), formatTime(&dc.EvaluatedAt)); err != nil {
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
