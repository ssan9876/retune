// Package csvexport writes the fleet's CSV exports: the device list and one
// compliance policy's results. The console's downloads and scheduled email
// reports both use it, so a report attachment is exactly what the download
// would have been.
package csvexport

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

// pageSize is how many rows each query pulls at a time, so a fleet of any
// size streams through constant memory. It is store.MaxPageLimit itself:
// the list queries clamp to that regardless of what's asked for.
const pageSize = store.MaxPageLimit

// injectionPrefixes are the leading characters a spreadsheet treats as the
// start of a formula (or, for tab/CR, as a way to smuggle extra cells or
// rows past a naive importer).
const injectionPrefixes = "=+-@\t\r"

// Safe defuses formula injection without touching cells that don't need
// it: a cell starting with a formula character gets a leading apostrophe,
// which every spreadsheet reads as "this is text".
func Safe(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(injectionPrefixes, s[0]) >= 0 {
		return "'" + s
	}
	return s
}

// Row writes one record through Safe on every cell, so no caller can forget
// to sanitize a column.
func Row(w *csv.Writer, cells ...string) error {
	safe := make([]string, len(cells))
	for i, c := range cells {
		safe[i] = Safe(c)
	}
	return w.Write(safe)
}

// Time renders a timestamp for a cell; nil (a device that has never checked
// in) is an empty cell rather than the zero time.
func Time(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// DevicesHeader is the device export's header row.
var DevicesHeader = []string{
	"hostname", "serial", "manufacturer", "model", "os_version", "os_build",
	"agent_version", "status", "compliance", "last_seen_at", "enrolled_at",
}

// WriteDevices writes every device the scope reaches, a page at a time,
// flushing after each so a large export is visibly progressing.
func WriteDevices(ctx context.Context, q *store.Queries, scope store.DeviceScope, w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(DevicesHeader); err != nil {
		return err
	}
	// Flushed now, so an empty fleet still gets its header.
	cw.Flush()
	if err := cw.Error(); err != nil {
		return err
	}
	for offset := 0; ; {
		rows, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{
			Page: store.Page{Limit: pageSize, Offset: offset}, Scope: scope,
		})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, len(rows))
		for i, d := range rows {
			ids[i] = d.ID
		}
		overall, err := q.ComplianceOverall(ctx, ids)
		if err != nil {
			return err
		}
		for _, d := range rows {
			if err := Row(cw,
				d.Hostname, d.Serial, d.Manufacturer, d.Model, d.OSVersion, d.OSBuild,
				d.AgentVersion, d.Status, overall[d.ID], Time(d.LastSeenAt), Time(&d.EnrolledAt),
			); err != nil {
				return err
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
		offset += len(rows)
		if offset >= total {
			return nil
		}
	}
}

// PolicyDevicesHeader is a policy export's header row.
var PolicyDevicesHeader = []string{"hostname", "state", "failures", "evaluated_at"}

// WritePolicyDevices writes one policy's result on each device the scope
// reaches, optionally only those in one state. Failures collapse to one
// cell, their details joined by semicolons.
func WritePolicyDevices(ctx context.Context, q *store.Queries, policyID uuid.UUID, state string, scope store.DeviceScope, w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(PolicyDevicesHeader); err != nil {
		return err
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return err
	}
	for offset := 0; ; {
		rows, total, err := q.ListPolicyCompliance(ctx, policyID, state, store.Page{Limit: pageSize, Offset: offset}, scope)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, dc := range rows {
			var failures []compliance.Failure
			if len(dc.Failures) > 0 {
				if err := json.Unmarshal(dc.Failures, &failures); err != nil {
					return err
				}
			}
			details := make([]string, 0, len(failures))
			for _, f := range failures {
				details = append(details, f.Detail)
			}
			if err := Row(cw, dc.Hostname, dc.State, strings.Join(details, "; "), Time(&dc.EvaluatedAt)); err != nil {
				return err
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
		offset += len(rows)
		if offset >= total {
			return nil
		}
	}
}
