package app_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// TestRemoteSession: an administrator opens a shell on a device, what is
// typed reaches the device, what it writes comes back, all of it is kept,
// and either side can end it.
func TestRemoteSession(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	help := signedIn(t, a, srv, store.RoleHelpdesk)
	id, agent := enrollDevice(t, a, srv, "PC-REMOTE")
	_, stranger := enrollDevice(t, a, srv, "PC-STRANGER")

	start := "/devices/" + id.String() + "/remote-sessions"
	if status, _ := admin.do(http.MethodPost, start, map[string]any{"reason": ""}); status != http.StatusBadRequest {
		t.Fatalf("no reason: %d", status)
	}
	if status, _ := help.do(http.MethodPost, start, map[string]any{"reason": "ticket 7"}); status != http.StatusForbidden {
		t.Fatalf("helpdesk: %d", status)
	}
	tok := makeToken(t, admin, "automation", store.RoleAdmin)
	if status, _ := bearer(t, a, srv, tok.Token, http.MethodPost, start, map[string]any{"reason": "x"}); status != http.StatusForbidden {
		t.Fatalf("a token: %d", status)
	}
	status, body := admin.do(http.MethodPost, start, map[string]any{"reason": "ticket 7: printer queue stuck"})
	if status != http.StatusCreated {
		t.Fatalf("start: %d %s", status, body)
	}
	session := decodeJSON[struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}](t, body)
	if session.Status != store.RemoteWaiting {
		t.Fatalf("session = %+v", session)
	}

	// The device is told at its check-in.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK || !strings.Contains(string(body), `"type":"remote_shell"`) || !strings.Contains(string(body), session.ID) {
		t.Fatalf("checkin: %d %s", status, body)
	}

	agentBase := srv.URL + "/api/agent/v1/remote-sessions/" + session.ID
	if status, body := admin.do(http.MethodPost, "/remote-sessions/"+session.ID+"/input", map[string]any{"data": "Get-Service Spooler\n"}); status != http.StatusNoContent {
		t.Fatalf("input: %d %s", status, body)
	}
	status, body = send(t, agent, http.MethodGet, agentBase+"/input?after=0", nil)
	in := decodeJSON[protocol.RemoteInputResponse](t, body)
	if status != http.StatusOK || len(in.Chunks) != 1 || in.Chunks[0].Data != "Get-Service Spooler\n" || in.Ended {
		t.Fatalf("agent input: %d %s", status, body)
	}
	// Another device can't join it.
	if status, _ := send(t, stranger, http.MethodGet, agentBase+"/input?after=0", nil); status != http.StatusNotFound {
		t.Fatalf("a stranger polling: %d", status)
	}
	if status, _ := send(t, stranger, http.MethodPost, agentBase+"/output", protocol.RemoteOutputRequest{Stream: "out", Data: "lies"}); status != http.StatusNotFound {
		t.Fatalf("a stranger writing: %d", status)
	}

	// Output reaches a console already waiting for it.
	type transcript struct {
		Session struct {
			Status    string `json:"status"`
			EndReason string `json:"end_reason"`
		} `json:"session"`
		Chunks []protocol.RemoteChunk `json:"chunks"`
	}
	after := strconv.FormatInt(in.Chunks[0].Seq, 10)
	waited := make(chan transcript, 1)
	go func() {
		_, body := admin.do(http.MethodGet, "/remote-sessions/"+session.ID+"?wait=1&after="+after, nil)
		var tr transcript
		_ = json.Unmarshal(body, &tr)
		waited <- tr
	}()
	time.Sleep(300 * time.Millisecond)
	if status, body := send(t, agent, http.MethodPost, agentBase+"/output", protocol.RemoteOutputRequest{
		Stream: protocol.RemoteStreamOut, Data: "Running  Spooler  Print Spooler\r\n"}); status != http.StatusNoContent {
		t.Fatalf("output: %d %s", status, body)
	}
	select {
	case tr := <-waited:
		if len(tr.Chunks) != 1 || tr.Chunks[0].Stream != "out" || tr.Session.Status != store.RemoteActive {
			t.Fatalf("waited transcript = %+v", tr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the waiting console was never answered")
	}

	// The whole transcript, in order.
	_, body = admin.do(http.MethodGet, "/remote-sessions/"+session.ID+"?after=0", nil)
	tr := decodeJSON[transcript](t, body)
	if len(tr.Chunks) != 2 || tr.Chunks[0].Stream != "in" || tr.Chunks[1].Stream != "out" {
		t.Fatalf("transcript = %+v", tr)
	}

	// Ended from the console: the device hears so, and can't write more.
	if status, _ := admin.do(http.MethodPost, "/remote-sessions/"+session.ID+"/end", nil); status != http.StatusNoContent {
		t.Fatalf("end: %d", status)
	}
	status, body = send(t, agent, http.MethodGet, agentBase+"/input?after="+after, nil)
	if status != http.StatusOK || !decodeJSON[protocol.RemoteInputResponse](t, body).Ended {
		t.Fatalf("after ending, input: %d %s", status, body)
	}
	if status, _ := send(t, agent, http.MethodPost, agentBase+"/output", protocol.RemoteOutputRequest{Stream: "out", Data: "late"}); status != http.StatusGone {
		t.Fatalf("output after ending: %d", status)
	}
	if status, _ := admin.do(http.MethodPost, "/remote-sessions/"+session.ID+"/input", map[string]any{"data": "more\n"}); status != http.StatusConflict {
		t.Fatalf("input after ending: %d", status)
	}
	_, body = admin.do(http.MethodGet, start, nil)
	if !strings.Contains(string(body), `"status":"ended"`) || !strings.Contains(string(body), "ended by ops@example.com") {
		t.Fatalf("list = %s", body)
	}
	_, body = admin.do(http.MethodGet, "/audit?action=remote_session", nil)
	if !strings.Contains(string(body), "remote_session.started") || !strings.Contains(string(body), "remote_session.ended") ||
		!strings.Contains(string(body), "printer queue stuck") {
		t.Fatalf("audit = %s", body)
	}
}
