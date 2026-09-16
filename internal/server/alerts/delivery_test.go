package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

// fakeMailer records what would have been sent, so the message a rule
// produces is tested without a socket to a mail relay.
type fakeMailer struct {
	to      []string
	subject string
	body    string
	err     error
}

func (m *fakeMailer) Send(_ context.Context, to []string, subject, body string) error {
	m.to, m.subject, m.body = to, subject, body
	return m.err
}

func testService(t *testing.T) *Service {
	t.Helper()
	key, err := secrets.LoadOrCreateFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		Key: key, Now: func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) },
		Log: slog.New(slog.DiscardHandler),
		// Configured, so an email channel is not refused for the wrong reason.
		SMTP: SMTP{Host: "smtp.example.com", Port: 587, From: "retune@example.com", StartTLS: true},
	}
}

func testMessage() Message {
	return Message{
		RuleName: "Quiet machines", Kind: store.AlertDeviceStale,
		Description: "a device has not checked in for 24 hours",
		At:          time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		Firing: []store.AlertSubject{
			{Key: "device:1", Subject: "PC-A has never checked in"},
			{Key: "device:2", Subject: "PC-B has not checked in since 2026-09-14 09:00 UTC"},
		},
		Resolved: []store.AlertSubject{{Key: "device:3", Subject: "PC-C has never checked in"}},
	}
}

func TestMessageSaysWhatChanged(t *testing.T) {
	m := testMessage()
	if got, want := m.Subject(), "Retune: Quiet machines - 2 new, 1 resolved"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	body := m.Body()
	for _, want := range []string{
		"Fires when: a device has not checked in for 24 hours",
		"Now firing (2):",
		"  - PC-A has never checked in",
		"Resolved (1):",
		"  - PC-C has never checked in",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
}

func TestMessageCountsTheOnesItDoesNotName(t *testing.T) {
	m := testMessage()
	m.Firing = nil
	for i := 0; i < maxNamed+5; i++ {
		m.Firing = append(m.Firing, store.AlertSubject{Key: "d", Subject: "PC-X is quiet"})
	}
	body := m.Body()
	// A fleet-wide fault is one message either way; what is bounded is how
	// long it is.
	if !strings.Contains(body, "... and 5 more.") {
		t.Errorf("body does not count the unnamed subjects:\n%s", body)
	}
	if n := strings.Count(body, "  - PC-X is quiet"); n != maxNamed {
		t.Errorf("named %d subjects, want %d", n, maxNamed)
	}
}

func TestDeliverEmail(t *testing.T) {
	s := testService(t)
	mailer := &fakeMailer{}
	s.Mailer = mailer
	ch := store.NotificationChannel{
		ID: uuid.Must(uuid.NewV7()), Kind: store.ChannelEmail,
		Config: []byte(`{"to":["ops@example.com"]}`),
	}
	if err := s.Deliver(context.Background(), ch, testMessage()); err != nil {
		t.Fatal(err)
	}
	if len(mailer.to) != 1 || mailer.to[0] != "ops@example.com" {
		t.Errorf("recipients = %v", mailer.to)
	}
	if !strings.Contains(mailer.subject, "Quiet machines") {
		t.Errorf("subject = %q", mailer.subject)
	}
}

func TestDeliverWebhookSignsTheBodyItSent(t *testing.T) {
	const secret = "s3cret-shared-with-the-receiver"
	var gotBody []byte
	var gotSignature string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSignature = r.Header.Get("X-Retune-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	s := testService(t)
	s.HTTP = srv.Client()
	id := uuid.Must(uuid.NewV7())
	ciphertext, nonce, err := s.SealSecret(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	ch := store.NotificationChannel{
		ID: id, Kind: store.ChannelWebhook,
		Config:           []byte(`{"url":` + quote(srv.URL) + `}`),
		SecretCiphertext: ciphertext, SecretNonce: nonce,
	}
	if err := s.Deliver(context.Background(), ch, testMessage()); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	// Over the exact bytes sent, so a receiver can verify what it read rather
	// than what it re-encoded.
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotSignature != want {
		t.Errorf("signature = %q, want %q", gotSignature, want)
	}

	var payload webhookPayload
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Kind != store.AlertDeviceStale || len(payload.Firing) != 2 || len(payload.Resolved) != 1 {
		t.Errorf("payload = %+v", payload)
	}
	if payload.Firing[0].Key != "device:1" {
		t.Errorf("payload does not carry the subject key: %+v", payload.Firing[0])
	}
}

func TestDeliverWebhookReportsWhatTheReceiverSaid(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such hook", http.StatusNotFound)
	}))
	defer srv.Close()

	s := testService(t)
	s.HTTP = srv.Client()
	ch := store.NotificationChannel{
		ID: uuid.Must(uuid.NewV7()), Kind: store.ChannelWebhook,
		Config: []byte(`{"url":` + quote(srv.URL) + `}`),
	}
	err := s.Deliver(context.Background(), ch, testMessage())
	// A misconfigured endpoint should read as a 404 in the delivery record,
	// not as silence.
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Deliver = %v, want the receiver's status", err)
	}
}

func TestParseChannelConfigRefusesWhatCannotBeDelivered(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		raw     string
		wantErr string
	}{
		{"an email channel needs somebody to mail", store.ChannelEmail, `{"to":[]}`, "at least one recipient"},
		{"a bad address", store.ChannelEmail, `{"to":["not an address"]}`, "is not an email address"},
		{"a url on an email channel", store.ChannelEmail, `{"to":["a@b.com"],"url":"https://x"}`, "url does not apply"},
		{"plain http", store.ChannelWebhook, `{"url":"http://hooks.example.com"}`, "must be an https URL"},
		{"recipients on a webhook", store.ChannelWebhook, `{"url":"https://x.example.com","to":["a@b.com"]}`, "to does not apply"},
		{"unknown kind", "carrier_pigeon", `{}`, "unsupported kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseChannelConfig(tc.kind, []byte(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseChannelConfig = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestMessageHeadersCannotBeSplit(t *testing.T) {
	// A hostname is device-reported text, and a newline in a Subject line is
	// how one header becomes two.
	raw := message("retune@example.com", []string{"ops@example.com"},
		"Retune: PC-A\r\nBcc: attacker@example.com", "body")
	headers, _, _ := strings.Cut(raw, "\r\n\r\n")
	// Folded into the Subject's own value is fine; a line of its own is not.
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Errorf("a newline in the subject added a header:\n%s", headers)
		}
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
