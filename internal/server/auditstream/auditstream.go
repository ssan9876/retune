// Package auditstream sends the audit log to a SIEM: over syslog (RFC 5424,
// UDP, TCP or TLS) or as newline-delimited JSON posted to an HTTPS webhook.
package auditstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"retune/internal/config"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
)

// Record is one audit entry as it leaves Retune; the webhook body is one per
// line, and a syslog message carries one as its text.
type Record struct {
	ID         string         `json:"id"`
	At         time.Time      `json:"at"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
}

func record(e store.AuditEntry) Record {
	return Record{
		ID: e.ID.String(), At: e.At.UTC(), Actor: e.Actor, Action: e.Action,
		TargetKind: e.TargetKind, TargetID: e.TargetID, Details: e.Details,
	}
}

// FromConfig builds the configured sinks; none when streaming is off.
func FromConfig(c config.AuditStreamConfig) []sweeper.AuditSink {
	var sinks []sweeper.AuditSink
	if c.SyslogAddress != "" {
		sinks = append(sinks, &Syslog{Network: c.SyslogNetwork, Address: c.SyslogAddress})
	}
	if c.WebhookURL != "" {
		w := &Webhook{URL: c.WebhookURL}
		if name, value, ok := strings.Cut(c.WebhookHeader, ":"); ok {
			w.HeaderName, w.HeaderValue = strings.TrimSpace(name), strings.TrimSpace(value)
		}
		sinks = append(sinks, w)
	}
	return sinks
}

const ioTimeout = 10 * time.Second

// Syslog sends each entry as one RFC 5424 message: facility 13 (log audit),
// severity 5 (notice), APP-NAME retune, MSGID the action, and the entry as
// JSON for the text. TCP and TLS use octet-counting framing (RFC 6587).
type Syslog struct {
	Network string // udp, tcp or tls
	Address string // host:port
	// TLSConfig overrides the TLS settings, for tests; nil verifies the
	// server against the system roots.
	TLSConfig *tls.Config
	// Hostname is sent as HOSTNAME; empty uses the machine's name.
	Hostname string
}

// Name implements sweeper.AuditSink.
func (s *Syslog) Name() string { return "syslog:" + s.Network + "://" + s.Address }

// Send implements sweeper.AuditSink. It dials afresh for every batch: runs
// are 30 seconds apart, and a new connection never finds a stale one.
func (s *Syslog) Send(ctx context.Context, entries []store.AuditEntry) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	host := s.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	host = printable(host, 255)
	for _, e := range entries {
		msg, err := syslogMessage(host, e)
		if err != nil {
			return err
		}
		if s.Network != "udp" {
			msg = append([]byte(fmt.Sprintf("%d ", len(msg))), msg...)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(ioTimeout))
		if _, err := conn.Write(msg); err != nil {
			return err
		}
	}
	return nil
}

func (s *Syslog) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: ioTimeout}
	switch s.Network {
	case "udp", "tcp":
		return d.DialContext(ctx, s.Network, s.Address)
	case "tls":
		cfg := s.TLSConfig
		if cfg == nil {
			host, _, _ := net.SplitHostPort(s.Address)
			cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		}
		return (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", s.Address)
	}
	return nil, fmt.Errorf("unknown syslog network %q", s.Network)
}

func syslogMessage(host string, e store.AuditEntry) ([]byte, error) {
	body, err := json.Marshal(record(e))
	if err != nil {
		return nil, err
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	head := fmt.Sprintf("<109>1 %s %s retune - %s - ",
		e.At.UTC().Format("2006-01-02T15:04:05.000000Z"), host, printable(e.Action, 32))
	return append([]byte(head), body...), nil
}

// printable fits a header field's rules: printable ASCII with no spaces, at
// most max characters, and "-" (the nil value) when nothing is left.
func printable(s string, max int) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < max; i++ {
		if c := s[i]; c >= '!' && c <= '~' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

// Webhook posts each batch as newline-delimited JSON, one Record a line. Any
// status but 2xx fails the batch, which is sent again on the next run, so the
// receiver should treat a record's id as the key for de-duplicating.
type Webhook struct {
	URL         string
	HeaderName  string
	HeaderValue string
	// Client overrides the HTTP client, for tests.
	Client *http.Client
}

// Name implements sweeper.AuditSink. The query string is left out: it may
// carry a token, and the name is stored and logged.
func (w *Webhook) Name() string {
	u, err := url.Parse(w.URL)
	if err != nil {
		return "webhook"
	}
	return "webhook:" + u.Scheme + "://" + u.Host + u.Path
}

// Send implements sweeper.AuditSink.
func (w *Webhook) Send(ctx context.Context, entries []store.AuditEntry) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range entries {
		if err := enc.Encode(record(e)); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if w.HeaderName != "" {
		req.Header.Set(w.HeaderName, w.HeaderValue)
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: ioTimeout}
	}
	// A redirect would carry the header somewhere nobody configured.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("webhook answered " + resp.Status)
	}
	return nil
}
