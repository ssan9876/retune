package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/alerts"
	"retune/internal/server/app"
	"retune/internal/server/store"
)

// errNoRelay is what a mail relay that is not there looks like from here.
var errNoRelay = errors.New("dial smtp.example.com:587: connection refused")

// capturingMailer stands in for the relay, so an end-to-end alert can be read
// without one.
type capturingMailer struct {
	sent []string
	err  error
}

func (m *capturingMailer) Send(_ context.Context, to []string, subject, body string) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, subject+"\n"+body)
	return nil
}

// alertingApp is a server whose email goes to a capturing mailer rather than
// a mail relay, with a channel and a stale-device rule already in place.
func alertingApp(t *testing.T) (*app.App, *httptest.Server, *adminClient, *capturingMailer) {
	t.Helper()
	a, srv := newTestApp(t)
	mailer := &capturingMailer{}
	a.Alerts.Mailer = mailer
	// An email channel is refused outright on a deployment with no relay, so
	// the test server is given one.
	a.Alerts.SMTP = alerts.SMTP{Host: "smtp.example.com", Port: 587, From: "retune@example.com", StartTLS: true}
	return a, srv, signedIn(t, a, srv, store.RoleAdmin), mailer
}

func createChannel(t *testing.T, c *adminClient, body map[string]any) map[string]any {
	t.Helper()
	status, raw := c.do(http.MethodPost, "/notification-channels", body)
	if status != http.StatusCreated {
		t.Fatalf("create channel: %d %s", status, raw)
	}
	return decodeJSON[map[string]any](t, raw)
}

func TestAlertLifecycleFromRuleToEmail(t *testing.T) {
	a, srv, c, mailer := alertingApp(t)
	ctx := context.Background()

	ch := createChannel(t, c, map[string]any{
		"name": "Ops mailbox", "kind": "email",
		"config": map[string]any{"to": []string{"ops@example.com"}},
	})
	status, raw := c.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Quiet machines", "kind": store.AlertDeviceStale,
		"params": map[string]any{"hours": 1}, "channel_id": ch["id"],
	})
	if status != http.StatusCreated {
		t.Fatalf("create rule: %d %s", status, raw)
	}
	rule := decodeJSON[map[string]any](t, raw)
	if rule["description"] != "a device has not checked in for an hour" {
		t.Errorf("description = %v", rule["description"])
	}
	if rule["channel_name"] != "Ops mailbox" {
		t.Errorf("channel_name = %v, want the channel joined in", rule["channel_name"])
	}

	// A device that enrolled and never came back is exactly what the rule is
	// for; enrollDevice does not record a check-in.
	quiet, _ := enrollDevice(t, a, srv, "PC-QUIET")

	now := time.Now().UTC()
	q := a.Store.Q()
	changed, err := a.Alerts.EvaluateAll(ctx, q, now)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("first pass changed %d subjects, want 1", changed)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(mailer.sent))
	}
	if !strings.Contains(mailer.sent[0], "PC-QUIET has never checked in") {
		t.Errorf("message does not name the device:\n%s", mailer.sent[0])
	}

	// The whole point of the state table: the same fault on the next tick is
	// not a second email.
	if changed, err := a.Alerts.EvaluateAll(ctx, q, now.Add(5*time.Minute)); err != nil || changed != 0 {
		t.Fatalf("second pass changed %d (err %v), want 0", changed, err)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("sent %d messages after a second pass, want still 1", len(mailer.sent))
	}

	// It is still firing, and the console can say since when.
	status, raw = c.do(http.MethodGet, "/alerts", nil)
	firing := decodeJSON[struct {
		Items []struct {
			RuleName   string  `json:"rule_name"`
			Subject    string  `json:"subject"`
			NotifiedAt *string `json:"notified_at"`
		} `json:"items"`
	}](t, raw)
	if status != http.StatusOK || len(firing.Items) != 1 {
		t.Fatalf("firing alerts: %d %s", status, raw)
	}
	if firing.Items[0].RuleName != "Quiet machines" || firing.Items[0].NotifiedAt == nil {
		t.Errorf("firing = %+v, want it notified", firing.Items[0])
	}

	// The device comes back, and the all-clear goes out once.
	enrollDevice(t, a, srv, "PC-QUIET-2")
	if err := q.RecordCheckin(ctx, store.DefaultTenantID, quiet, "0.3.0", now); err != nil {
		t.Fatal(err)
	}
	// PC-QUIET-2 has never checked in either, so it starts firing on the same
	// pass the first one clears: one message carries both.
	if _, err := a.Alerts.EvaluateAll(ctx, q, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(mailer.sent))
	}
	last := mailer.sent[1]
	if !strings.Contains(last, "Resolved (1):") || !strings.Contains(last, "PC-QUIET has never checked in") {
		t.Errorf("all-clear missing from:\n%s", last)
	}
	if !strings.Contains(last, "PC-QUIET-2 has never checked in") {
		t.Errorf("the newly quiet machine is missing from:\n%s", last)
	}

	// And every attempt is on the record.
	status, raw = c.do(http.MethodGet, "/alert-deliveries", nil)
	deliveries := decodeJSON[struct {
		Items []struct {
			RuleName string `json:"rule_name"`
			OK       bool   `json:"ok"`
			Firing   int    `json:"firing"`
			Resolved int    `json:"resolved"`
		} `json:"items"`
	}](t, raw)
	if status != http.StatusOK || len(deliveries.Items) != 2 {
		t.Fatalf("deliveries: %d %s", status, raw)
	}
	if !deliveries.Items[0].OK || deliveries.Items[0].Resolved != 1 {
		t.Errorf("newest delivery = %+v", deliveries.Items[0])
	}
}

func TestAFailedDeliveryIsRetriedOnTheNextPass(t *testing.T) {
	a, srv, c, mailer := alertingApp(t)
	ctx := context.Background()

	ch := createChannel(t, c, map[string]any{
		"name": "Ops mailbox", "kind": "email",
		"config": map[string]any{"to": []string{"ops@example.com"}},
	})
	if status, raw := c.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Quiet machines", "kind": store.AlertDeviceStale,
		"params": map[string]any{"hours": 1}, "channel_id": ch["id"],
	}); status != http.StatusCreated {
		t.Fatalf("create rule: %d %s", status, raw)
	}
	enrollDevice(t, a, srv, "PC-QUIET")

	mailer.err = errNoRelay
	now := time.Now().UTC()
	q := a.Store.Q()
	if _, err := a.Alerts.EvaluateAll(ctx, q, now); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent) != 0 {
		t.Fatalf("a failing relay sent %d messages", len(mailer.sent))
	}

	// Nothing was announced, so the subject still counts as new and the next
	// tick tries again rather than losing the alert.
	mailer.err = nil
	if _, err := a.Alerts.EvaluateAll(ctx, q, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("sent %d messages after the relay recovered, want 1", len(mailer.sent))
	}

	// The failure is on the record with the relay's own words.
	_, raw := c.do(http.MethodGet, "/alert-deliveries", nil)
	if !strings.Contains(string(raw), errNoRelay.Error()) {
		t.Errorf("deliveries do not record why the first attempt failed: %s", raw)
	}
}

func TestChannelSecretsAreWriteOnlyAndChannelsInUseSurvive(t *testing.T) {
	_, _, c, _ := alertingApp(t)

	ch := createChannel(t, c, map[string]any{
		"name": "Ops webhook", "kind": "webhook",
		"config": map[string]any{"url": "https://hooks.example.com/retune"},
		"secret": "s3cret",
	})
	if ch["has_secret"] != true {
		t.Errorf("has_secret = %v, want true", ch["has_secret"])
	}
	// The secret itself is never serialised, to any role.
	if raw, _ := json.Marshal(ch); strings.Contains(string(raw), "s3cret") {
		t.Errorf("the channel serialised its secret: %s", raw)
	}

	if status, raw := c.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Failed deployments", "kind": store.AlertDeploymentFailed,
		"channel_id": ch["id"],
	}); status != http.StatusCreated {
		t.Fatalf("create rule: %d %s", status, raw)
	}
	// Deleting the channel would silently stop the rule, so it is refused
	// rather than cascading.
	status, raw := c.do(http.MethodDelete, "/notification-channels/"+ch["id"].(string), nil)
	if status != http.StatusConflict {
		t.Fatalf("delete channel in use = %d %s, want 409", status, raw)
	}
}

func TestAlertEndpointsRefuseBadRulesAndReadOnlyWrites(t *testing.T) {
	a, srv, c, _ := alertingApp(t)

	ch := createChannel(t, c, map[string]any{
		"name": "Ops webhook", "kind": "webhook",
		"config": map[string]any{"url": "https://hooks.example.com/retune"},
	})
	// A parameter that belongs to another kind is a mistake worth a 400.
	if status, raw := c.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Wrong", "kind": store.AlertDeploymentFailed,
		"params": map[string]any{"hours": 3}, "channel_id": ch["id"],
	}); status != http.StatusBadRequest {
		t.Errorf("rule with a foreign parameter = %d %s, want 400", status, raw)
	}
	// So is a webhook that is not https.
	if status, raw := c.do(http.MethodPost, "/notification-channels", map[string]any{
		"name": "Insecure", "kind": "webhook",
		"config": map[string]any{"url": "http://hooks.example.com"},
	}); status != http.StatusBadRequest {
		t.Errorf("plain-http webhook = %d %s, want 400", status, raw)
	}

	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := viewer.do(http.MethodGet, "/alert-rules", nil); status != http.StatusOK {
		t.Errorf("read-only listing rules = %d, want 200", status)
	}
	for _, path := range []string{"/notification-channels", "/alert-rules"} {
		if status, _ := viewer.do(http.MethodPost, path, map[string]any{"name": "nope"}); status != http.StatusForbidden {
			t.Errorf("read-only POST %s = %d, want 403", path, status)
		}
	}
	// Sending a test makes the server talk to the outside world, so it is a
	// write too.
	if status, _ := viewer.do(http.MethodPost, "/notification-channels/"+ch["id"].(string)+"/test", nil); status != http.StatusForbidden {
		t.Errorf("read-only test = %d, want 403", status)
	}
}

func TestAnEmailChannelIsRefusedWithNoRelay(t *testing.T) {
	a, srv := newTestApp(t)
	// The default test app has no SMTP configuration, which is the state a
	// fresh deployment is in.
	c := signedIn(t, a, srv, store.RoleAdmin)
	status, raw := c.do(http.MethodPost, "/notification-channels", map[string]any{
		"name": "Ops mailbox", "kind": "email",
		"config": map[string]any{"to": []string{"ops@example.com"}},
	})
	if status != http.StatusBadRequest || !strings.Contains(string(raw), "SMTP_HOST") {
		t.Fatalf("email channel with no relay = %d %s, want 400 naming the setting", status, raw)
	}
}

// A webhook URL is often the credential itself, so a read-only account sees
// only where it goes, never the path.
func TestReadOnlyAdminsSeeOnlyAWebhooksHost(t *testing.T) {
	a, srv, admin, _ := alertingApp(t)
	ch := createChannel(t, admin, map[string]any{
		"name": "Ops chat", "kind": "webhook",
		"config": map[string]any{"url": "https://hooks.example.com/services/T000/B000/SECRETSECRET"},
	})
	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	for _, path := range []string{"/notification-channels", "/notification-channels/" + ch["id"].(string)} {
		status, body := viewer.do(http.MethodGet, path, nil)
		if status != http.StatusOK || strings.Contains(string(body), "SECRETSECRET") || !strings.Contains(string(body), "hooks.example.com") {
			t.Errorf("%s as read-only: %d %s", path, status, body)
		}
	}
	if _, body := admin.do(http.MethodGet, "/notification-channels", nil); !strings.Contains(string(body), "SECRETSECRET") {
		t.Errorf("an admin should see the whole URL to edit it: %s", body)
	}
}

// A rule that can't be saved as asked is the caller's mistake, said as one:
// a 400 naming what's wrong, never a server error.
func TestAnInvalidRuleIsABadRequest(t *testing.T) {
	_, _, c, _ := alertingApp(t)
	ch := createChannel(t, c, map[string]any{
		"name": "Ops mailbox", "kind": "email",
		"config": map[string]any{"to": []string{"ops@example.com"}},
	})
	for name, body := range map[string]map[string]any{
		"no name":         {"kind": store.AlertDeviceStale, "params": map[string]any{"hours": 1}, "channel_id": ch["id"]},
		"no channel":      {"name": "Quiet", "kind": store.AlertDeviceStale, "params": map[string]any{"hours": 1}},
		"bad channel id":  {"name": "Quiet", "kind": store.AlertDeviceStale, "params": map[string]any{"hours": 1}, "channel_id": "nope"},
		"unknown channel": {"name": "Quiet", "kind": store.AlertDeviceStale, "params": map[string]any{"hours": 1}, "channel_id": uuid.NewString()},
	} {
		if status, raw := c.do(http.MethodPost, "/alert-rules", body); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, status, raw)
		}
	}
}
