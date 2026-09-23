package auditstream_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/server/auditstream"
	"retune/internal/server/store"
)

func entries() []store.AuditEntry {
	at := time.Date(2026, 9, 22, 10, 0, 0, 123456000, time.UTC)
	return []store.AuditEntry{
		{ID: uuid.New(), Actor: "alice", Action: "device.delete", TargetKind: "device", TargetID: "d1",
			Details: map[string]any{"hostname": "PC-1"}, At: at},
		{ID: uuid.New(), Actor: "bob smith", Action: "odd action\n", TargetKind: "script", TargetID: "s1",
			Details: map[string]any{}, At: at.Add(time.Second)},
	}
}

// readOctetCounted reads one RFC 6587 octet-counted frame.
func readOctetCounted(r *bufio.Reader) (string, error) {
	n, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// acceptFrames accepts one connection and reads n frames from it.
func acceptFrames(ln net.Listener, n int) <-chan []string {
	got := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		var frames []string
		for i := 0; i < n; i++ {
			f, err := readOctetCounted(r)
			if err != nil {
				frames = append(frames, "error: "+err.Error())
				break
			}
			frames = append(frames, f)
		}
		got <- frames
	}()
	return got
}

func waitFrames(t *testing.T, got <-chan []string) []string {
	t.Helper()
	select {
	case f := <-got:
		return f
	case <-time.After(10 * time.Second):
		t.Fatal("no messages arrived")
		return nil
	}
}

func checkMessage(t *testing.T, msg string, want store.AuditEntry, msgid string) {
	t.Helper()
	prefix := "<109>1 " + want.At.UTC().Format("2006-01-02T15:04:05.000000Z") + " test-host retune - " + msgid + " - "
	if !strings.HasPrefix(msg, prefix) {
		t.Fatalf("message %q\nwant prefix %q", msg, prefix)
	}
	var rec auditstream.Record
	if err := json.Unmarshal([]byte(strings.TrimPrefix(msg, prefix)), &rec); err != nil {
		t.Fatalf("message body: %v", err)
	}
	if rec.ID != want.ID.String() || rec.Actor != want.Actor || rec.Action != want.Action || rec.TargetID != want.TargetID {
		t.Fatalf("record = %+v, want %+v", rec, want)
	}
}

func TestSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := acceptFrames(ln, 2)

	s := &auditstream.Syslog{Network: "tcp", Address: ln.Addr().String(), Hostname: "test-host"}
	if s.Name() != "syslog:tcp://"+ln.Addr().String() {
		t.Fatalf("name = %q", s.Name())
	}
	es := entries()
	if err := s.Send(context.Background(), es); err != nil {
		t.Fatal(err)
	}
	msgs := waitFrames(t, got)
	if len(msgs) != 2 {
		t.Fatalf("frames = %q", msgs)
	}
	checkMessage(t, msgs[0], es[0], "device.delete")
	// Spaces and control characters can't appear in a MSGID.
	checkMessage(t, msgs[1], es[1], "odd_action_")
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := &auditstream.Syslog{Network: "udp", Address: pc.LocalAddr().String(), Hostname: "test-host"}
	es := entries()
	if err := s.Send(context.Background(), es[:1]); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	// One datagram per message, with no length prefix.
	checkMessage(t, string(buf[:n]), es[0], "device.delete")
}

func TestSyslogTLS(t *testing.T) {
	// httptest's server supplies a certificate for 127.0.0.1 and example.com.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	cert := srv.TLS.Certificates[0]
	srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := acceptFrames(ln, 1)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	s := &auditstream.Syslog{Network: "tls", Address: ln.Addr().String(), Hostname: "test-host",
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
	es := entries()
	if err := s.Send(context.Background(), es[:1]); err != nil {
		t.Fatal(err)
	}
	msgs := waitFrames(t, got)
	if len(msgs) != 1 {
		t.Fatalf("frames = %q", msgs)
	}
	checkMessage(t, msgs[0], es[0], "device.delete")

	// Without the test root, the server isn't trusted.
	acceptFrames(ln, 1)
	untrusted := &auditstream.Syslog{Network: "tls", Address: ln.Addr().String()}
	if err := untrusted.Send(context.Background(), es[:1]); err == nil {
		t.Fatal("sent to a server with an untrusted certificate")
	}
}

func TestSyslogUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s := &auditstream.Syslog{Network: "tcp", Address: addr}
	if err := s.Send(context.Background(), entries()); err == nil {
		t.Fatal("expected an error from a closed port")
	}
}

func TestWebhook(t *testing.T) {
	var gotHeader, gotType string
	var lines []string
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		lines = strings.Split(strings.TrimRight(string(body), "\n"), "\n")
		w.WriteHeader(status)
	}))
	defer srv.Close()

	sinks := auditstream.FromConfig(config.AuditStreamConfig{
		WebhookURL: srv.URL + "/ingest?token=secret", WebhookHeader: "Authorization: Bearer abc",
	})
	if len(sinks) != 1 {
		t.Fatalf("sinks = %d", len(sinks))
	}
	w := sinks[0].(*auditstream.Webhook)
	w.Client = srv.Client()
	// The name is stored and logged, so the query string stays out of it.
	if w.Name() != "webhook:"+srv.URL+"/ingest" {
		t.Fatalf("name = %q", w.Name())
	}
	es := entries()
	if err := w.Send(context.Background(), es); err != nil {
		t.Fatal(err)
	}
	if gotHeader != "Bearer abc" || gotType != "application/x-ndjson" {
		t.Fatalf("headers: authorization %q, content-type %q", gotHeader, gotType)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	for i, line := range lines {
		var rec auditstream.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.ID != es[i].ID.String() {
			t.Fatalf("line %d = %q (%v)", i, line, err)
		}
	}

	status = http.StatusInternalServerError
	if err := w.Send(context.Background(), es); err == nil {
		t.Fatal("a 500 must fail the batch")
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	w := &auditstream.Webhook{URL: srv.URL, HeaderName: "Authorization", HeaderValue: "x", Client: srv.Client()}
	if err := w.Send(context.Background(), entries()); err == nil {
		t.Fatal("a redirect must fail the batch")
	}
	if hit {
		t.Fatal("followed the redirect")
	}
}

func TestFromConfig(t *testing.T) {
	if n := len(auditstream.FromConfig(config.AuditStreamConfig{})); n != 0 {
		t.Fatalf("no config gave %d sinks", n)
	}
	sinks := auditstream.FromConfig(config.AuditStreamConfig{
		SyslogNetwork: "tls", SyslogAddress: "siem.example:6514", WebhookURL: "https://h.example/x",
	})
	if len(sinks) != 2 || sinks[0].Name() != "syslog:tls://siem.example:6514" || sinks[1].Name() != "webhook:https://h.example/x" {
		t.Fatalf("sinks = %v", sinks)
	}
}
