package app_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

// parseCSV decodes a response body into its header row and data rows,
// failing the test if the body is not well-formed CSV.
func parseCSV(t *testing.T, body []byte) (header []string, rows [][]string) {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v\nbody: %s", err, body)
	}
	if len(records) == 0 {
		t.Fatalf("csv has no rows at all")
	}
	return records[0], records[1:]
}

// TestExportDevicesCSV covers the device export endpoint (spec §5): its
// content type and attachment header, its exact column order, one row per
// device, and formula-injection guarding on a hostname that opens with
// =HYPERLINK(...) - the classic CSV-injection payload.
func TestExportDevicesCSV(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	enrollDevice(t, a, srv, "PC-PLAIN")
	enrollDevice(t, a, srv, `=HYPERLINK("http://evil.example","click me")`)

	status, headers, body := admin.doWithHeaders(http.MethodGet, "/devices/export.csv", nil)
	if status != http.StatusOK {
		t.Fatalf("export devices: %d %s", status, body)
	}
	if ct := headers.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := headers.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("content-disposition = %q, want an attachment", cd)
	}

	header, rows := parseCSV(t, body)
	wantHeader := []string{
		"hostname", "serial", "manufacturer", "model", "os_version", "os_build",
		"agent_version", "status", "compliance", "last_seen_at", "enrolled_at",
	}
	if len(header) != len(wantHeader) {
		t.Fatalf("header = %v, want %v", header, wantHeader)
	}
	for i, col := range wantHeader {
		if header[i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, header[i], col)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (one per enrolled device)", len(rows))
	}

	foundInjected := false
	for _, row := range rows {
		hostname := row[0]
		if strings.HasPrefix(hostname, `'=HYPERLINK`) {
			foundInjected = true
		}
		// No cell in a legitimate row should still start with a raw formula
		// prefix: csvSafe must have caught every one, not just the hostname.
		for _, cell := range row {
			if cell != "" && strings.IndexByte("=+-@\t\r", cell[0]) >= 0 {
				t.Fatalf("unsanitized cell %q in row %v", cell, row)
			}
		}
	}
	if !foundInjected {
		t.Fatalf("expected a hostname prefixed with ' guarding =HYPERLINK(...), rows: %v", rows)
	}

	// Read-only admins may read exports; only writes are gated.
	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _, body := ro.doWithHeaders(http.MethodGet, "/devices/export.csv", nil); status != http.StatusOK {
		t.Fatalf("read-only export devices: %d %s", status, body)
	}
}

// TestExportDevicesCSVEmpty covers the zero-device case: csv.Writer buffers
// internally, and exportDevices' paging loop never runs an iteration when
// there is nothing to page through, so the header row must be flushed on its
// own rather than only after a page of rows.
func TestExportDevicesCSVEmpty(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, headers, body := admin.doWithHeaders(http.MethodGet, "/devices/export.csv", nil)
	if status != http.StatusOK {
		t.Fatalf("export devices: %d %s", status, body)
	}
	if ct := headers.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}

	wantHeader := []string{
		"hostname", "serial", "manufacturer", "model", "os_version", "os_build",
		"agent_version", "status", "compliance", "last_seen_at", "enrolled_at",
	}
	header, rows := parseCSV(t, body)
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0 for an empty fleet", len(rows))
	}
	if len(header) != len(wantHeader) {
		t.Fatalf("header = %v, want %v", header, wantHeader)
	}
	for i, col := range wantHeader {
		if header[i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, header[i], col)
		}
	}
	if got := strings.TrimRight(string(body), "\r\n"); got != strings.Join(wantHeader, ",") {
		t.Fatalf("body = %q, want exactly the header row", body)
	}
}

// TestExportPolicyDevicesCSV covers the policy device export endpoint (spec
// §5): headers, columns, one row per device the policy has a result for, and
// read-only access.
func TestExportPolicyDevicesCSV(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	_, client := enrollDevice(t, a, srv, "PC-EXPORT-POLICY")

	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "No pending reboot",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policy.ID.String(),
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	}); status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}
	if status, body := send(t, client, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-EXPORT-POLICY", PendingReboot: true,
	}); status != http.StatusOK {
		t.Fatalf("upload inventory: %d %s", status, body)
	}

	status, headers, body := admin.doWithHeaders(http.MethodGet, "/compliance-policies/"+policy.ID.String()+"/devices/export.csv", nil)
	if status != http.StatusOK {
		t.Fatalf("export policy devices: %d %s", status, body)
	}
	if ct := headers.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := headers.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("content-disposition = %q, want an attachment", cd)
	}

	header, rows := parseCSV(t, body)
	wantHeader := []string{"hostname", "state", "failures", "evaluated_at"}
	if len(header) != len(wantHeader) {
		t.Fatalf("header = %v, want %v", header, wantHeader)
	}
	for i, col := range wantHeader {
		if header[i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, header[i], col)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0][0] != "PC-EXPORT-POLICY" {
		t.Fatalf("hostname = %q", rows[0][0])
	}
	if rows[0][1] != store.ComplianceNonCompliant {
		t.Fatalf("state = %q, want %q", rows[0][1], store.ComplianceNonCompliant)
	}
	if rows[0][2] == "" {
		t.Fatalf("failures column is empty for a non-compliant device")
	}

	// An unknown policy ID is a 404, not a CSV body.
	if status, _, _ := admin.doWithHeaders(http.MethodGet,
		"/compliance-policies/"+uuid.Must(uuid.NewV7()).String()+"/devices/export.csv", nil); status != http.StatusNotFound {
		t.Fatalf("unknown policy export: %d, want 404", status)
	}

	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _, body := ro.doWithHeaders(http.MethodGet,
		"/compliance-policies/"+policy.ID.String()+"/devices/export.csv", nil); status != http.StatusOK {
		t.Fatalf("read-only export policy devices: %d %s", status, body)
	}
}

// TestExportPolicyDevicesCSVEmpty covers a policy with zero compliance
// results (never evaluated, or assigned to no one): the same zero-row case
// as TestExportDevicesCSVEmpty, for the other export handler's own
// unconditional-flush fix.
func TestExportPolicyDevicesCSVEmpty(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "Never assigned",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	status, headers, body := admin.doWithHeaders(http.MethodGet,
		"/compliance-policies/"+policy.ID.String()+"/devices/export.csv", nil)
	if status != http.StatusOK {
		t.Fatalf("export policy devices: %d %s", status, body)
	}
	if ct := headers.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}

	wantHeader := []string{"hostname", "state", "failures", "evaluated_at"}
	header, rows := parseCSV(t, body)
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0 for a policy with no compliance results", len(rows))
	}
	if len(header) != len(wantHeader) {
		t.Fatalf("header = %v, want %v", header, wantHeader)
	}
	for i, col := range wantHeader {
		if header[i] != col {
			t.Fatalf("header[%d] = %q, want %q", i, header[i], col)
		}
	}
	if got := strings.TrimRight(string(body), "\r\n"); got != strings.Join(wantHeader, ",") {
		t.Fatalf("body = %q, want exactly the header row", body)
	}
}

// TestAuditFilterAndExport covers the audit log's filters, shared by the
// listing and the CSV export, and formula-guarding in the export.
func TestAuditFilterAndExport(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, e := range []store.AuditEntry{
		{Actor: "carol", Action: "device.delete", TargetKind: "device", TargetID: "d1", At: old},
		{Actor: "=cmd|' /C calc'!A0", Action: "script.create", TargetKind: "script", TargetID: "s1",
			Details: map[string]any{"name": "@SUM(1)"}},
	} {
		if err := a.Store.Q().InsertAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	var list struct {
		Items []struct{ Actor, Action string } `json:"items"`
		Total int                              `json:"total"`
	}
	get := func(q string) {
		t.Helper()
		status, body := admin.do(http.MethodGet, "/audit?"+q, nil)
		if status != http.StatusOK {
			t.Fatalf("audit?%s: %d %s", q, status, body)
		}
		list.Items = nil
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
	}
	get("actor=CAROL")
	if list.Total != 1 || list.Items[0].Action != "device.delete" {
		t.Fatalf("actor filter: %+v", list)
	}
	get("action=script.")
	if list.Total != 1 || list.Items[0].Action != "script.create" {
		t.Fatalf("action filter: %+v", list)
	}
	get("until=2026-02-01T00:00:00Z")
	if list.Total != 1 || list.Items[0].Actor != "carol" {
		t.Fatalf("until filter: %+v", list)
	}
	get("since=2026-02-01T00:00:00Z&action=device.delete")
	if list.Total != 0 {
		t.Fatalf("since filter: %+v", list)
	}
	if status, _ := admin.do(http.MethodGet, "/audit?since=yesterday", nil); status != http.StatusBadRequest {
		t.Fatalf("bad since: %d", status)
	}

	status, headers, body := admin.doWithHeaders(http.MethodGet, "/audit/export.csv?action=script.", nil)
	if status != http.StatusOK {
		t.Fatalf("export audit: %d %s", status, body)
	}
	if cd := headers.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("content-disposition = %q", cd)
	}
	header, rows := parseCSV(t, body)
	if strings.Join(header, ",") != "at,actor,action,target_kind,target_id,details,id" {
		t.Fatalf("header = %v", header)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	if !strings.HasPrefix(rows[0][1], "'=") {
		t.Fatalf("actor cell %q isn't guarded", rows[0][1])
	}
	if !strings.Contains(rows[0][5], `"name":"@SUM(1)"`) {
		t.Fatalf("details cell = %q", rows[0][5])
	}

	// Everything, unfiltered: the entries above plus the admin's sign-in.
	_, _, body = admin.doWithHeaders(http.MethodGet, "/audit/export.csv", nil)
	if _, rows := parseCSV(t, body); len(rows) < 3 {
		t.Fatalf("unfiltered export has %d rows", len(rows))
	}
}
