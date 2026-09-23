package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"retune/internal/server/alerts"
	"retune/internal/server/store"
)

// reportMailer records what scheduled reports send.
type reportMailer struct {
	to      [][]string
	subject []string
	files   [][]alerts.Attachment
	err     error
}

func (m *reportMailer) Send(context.Context, []string, string, string) error { return m.err }

func (m *reportMailer) SendWithAttachments(_ context.Context, to []string, subject, _ string, files []alerts.Attachment) error {
	if m.err != nil {
		return m.err
	}
	m.to, m.subject, m.files = append(m.to, to), append(m.subject, subject), append(m.files, files)
	return nil
}

type reportResp struct {
	ID         string    `json:"id"`
	Recipients []string  `json:"recipients"`
	NextRunAt  time.Time `json:"next_run_at"`
	LastSentAt *string   `json:"last_sent_at"`
	LastError  string    `json:"last_error"`
}

// TestScheduledReports: a report is checked, emailed with its CSV on its
// schedule or on demand, and a failed send is recorded, not retried
// constantly.
func TestScheduledReports(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	enrollDevice(t, a, srv, "PC-REPORTED")
	daily := map[string]any{"name": "Fleet", "kind": "devices", "recipients": []string{"Auditor <audit@example.com>"},
		"frequency": "daily", "hour": 6, "timezone": "Europe/London"}

	// No relay, no reports: better refused now than never arriving.
	if status, body := admin.do(http.MethodPost, "/reports", daily); status != http.StatusBadRequest || !strings.Contains(string(body), "SMTP") {
		t.Fatalf("with no relay: %d %s", status, body)
	}
	mailer := &reportMailer{}
	a.Alerts.Mailer = mailer
	a.Reports.Mailer = mailer

	with := func(k string, v any) map[string]any {
		out := map[string]any{}
		for key, val := range daily {
			out[key] = val
		}
		out[k] = v
		return out
	}
	for name, bad := range map[string]map[string]any{
		"a bad address":    with("recipients", []string{"not an address"}),
		"no recipients":    with("recipients", []string{}),
		"a bad time zone":  with("timezone", "Mars/Olympus"),
		"hourly":           with("frequency", "hourly"),
		"a policy":         with("policy_id", "8b8b8b8b-0000-0000-0000-000000000000"),
		"no policy":        with("kind", "compliance"),
		"an unknown kind":  with("kind", "everything"),
		"too late an hour": with("hour", 24),
	} {
		if status, body := admin.do(http.MethodPost, "/reports", bad); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, status, body)
		}
	}

	status, body := admin.do(http.MethodPost, "/reports", daily)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	report := decodeJSON[reportResp](t, body)
	if len(report.Recipients) != 1 || report.Recipients[0] != "audit@example.com" || !report.NextRunAt.After(time.Now()) {
		t.Fatalf("report = %+v", report)
	}

	// Sent on demand, with the device export attached.
	if status, body := admin.do(http.MethodPost, "/reports/"+report.ID+"/send", nil); status != http.StatusOK {
		t.Fatalf("send now: %d %s", status, body)
	}
	if len(mailer.files) != 1 || len(mailer.files[0]) != 1 {
		t.Fatalf("sent %+v", mailer.files)
	}
	csv := string(mailer.files[0][0].Data)
	if !strings.HasPrefix(mailer.files[0][0].Name, "devices-") || !strings.HasPrefix(csv, "hostname,serial") ||
		!strings.Contains(csv, "PC-REPORTED") || mailer.subject[0] != "Retune report: Fleet" {
		t.Fatalf("attachment %q: %s", mailer.files[0][0].Name, csv)
	}

	// Not due yet, nothing goes; once due, it goes and moves to the next day.
	if n, err := a.Reports.SendDue(context.Background()); err != nil || n != 0 {
		t.Fatalf("before it is due: %d, %v", n, err)
	}
	a.Reports.Now = func() time.Time { return report.NextRunAt.Add(time.Minute) }
	if n, err := a.Reports.SendDue(context.Background()); err != nil || n != 1 {
		t.Fatalf("when due: %d, %v", n, err)
	}
	_, body = admin.do(http.MethodGet, "/reports/"+report.ID, nil)
	after := decodeJSON[reportResp](t, body)
	if want := report.NextRunAt.Add(24 * time.Hour); !after.NextRunAt.Equal(want) || after.LastSentAt == nil {
		t.Fatalf("after sending: next %s (want %s), last sent %v", after.NextRunAt, want, after.LastSentAt)
	}

	// A failed send is kept for the console and waits for the next run.
	mailer.err = errors.New("relay refused the message")
	a.Reports.Now = func() time.Time { return after.NextRunAt.Add(time.Minute) }
	if n, err := a.Reports.SendDue(context.Background()); err != nil || n != 0 {
		t.Fatalf("a failing send: %d, %v", n, err)
	}
	_, body = admin.do(http.MethodGet, "/reports/"+report.ID, nil)
	failed := decodeJSON[reportResp](t, body)
	if !strings.Contains(failed.LastError, "relay refused") || !failed.NextRunAt.After(after.NextRunAt) {
		t.Fatalf("after a failure: %+v", failed)
	}
	if status, _ := admin.do(http.MethodPost, "/reports/"+report.ID+"/send", nil); status != http.StatusBadGateway {
		t.Fatalf("send now, failing: %d", status)
	}
	mailer.err = nil
	a.Reports.Now = time.Now

	// A compliance report names a policy that exists.
	status, body = admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "Baseline", "rules": json.RawMessage(`[{"type":"no_pending_reboot"}]`),
	})
	if status != http.StatusCreated {
		t.Fatalf("create policy: %d %s", status, body)
	}
	policyID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	weekly := map[string]any{"name": "Failing devices", "kind": "compliance", "policy_id": policyID, "state": "non_compliant",
		"recipients": []string{"it@example.com"}, "frequency": "weekly", "weekday": 1, "hour": 7}
	status, body = admin.do(http.MethodPost, "/reports", weekly)
	if status != http.StatusCreated {
		t.Fatalf("create compliance report: %d %s", status, body)
	}
	cr := decodeJSON[reportResp](t, body)
	if status, body := admin.do(http.MethodPost, "/reports/"+cr.ID+"/send", nil); status != http.StatusOK {
		t.Fatalf("send compliance report: %d %s", status, body)
	}
	last := mailer.files[len(mailer.files)-1][0]
	if last.Name != "compliance-baseline-"+time.Now().UTC().Format("2006-01-02")+".csv" || !strings.HasPrefix(string(last.Data), "hostname,state,failures") {
		t.Fatalf("compliance attachment %q: %s", last.Name, last.Data)
	}

	if status, _ := admin.do(http.MethodDelete, "/reports/"+report.ID, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if status, _ := admin.do(http.MethodGet, "/reports/"+report.ID, nil); status != http.StatusNotFound {
		t.Fatalf("get deleted: %d", status)
	}
}
