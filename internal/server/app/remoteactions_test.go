package app_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type queuedResp struct {
	Commands []struct {
		ID       string `json:"id"`
		DeviceID string `json:"device_id"`
	} `json:"commands"`
}

// TestCollectLogsRoundTrip: an admin asks for logs, the device uploads its
// archive while the command runs, and an admin downloads it, which is
// audited. A read-only admin can't.
func TestCollectLogsRoundTrip(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	deviceID, agent := enrollDevice(t, a, srv, "PC-LOGS")

	status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{deviceID.String()}, "type": "collect_logs", "hours": 12,
	})
	if status != http.StatusCreated {
		t.Fatalf("queue: %d %s", status, body)
	}
	id := decodeJSON[queuedResp](t, body).Commands[0].ID

	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	cmds := decodeJSON[protocol.CheckinResponse](t, body).Commands
	if len(cmds) != 1 || cmds[0].Type != protocol.CommandCollectLogs || string(cmds[0].Payload) != `{"hours":12}` {
		t.Fatalf("delivered %+v", cmds)
	}
	upload := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			srv.URL+"/api/agent/v1/commands/"+id+"/artifact", bytes.NewReader([]byte("PK pretend zip")))
		res, err := agent.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := upload(); code != http.StatusConflict {
		t.Fatalf("upload before start: %d", code)
	}
	if status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/commands/"+id+"/start", nil); status != http.StatusNoContent {
		t.Fatalf("start: %d %s", status, body)
	}
	if code := upload(); code != http.StatusNoContent {
		t.Fatalf("upload: %d", code)
	}
	if code := upload(); code != http.StatusConflict {
		t.Fatalf("second upload: %d", code)
	}

	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _, _ := ro.doWithHeaders(http.MethodGet, "/commands/"+id+"/artifact", nil); status != http.StatusForbidden {
		t.Fatalf("read-only download: %d", status)
	}
	status, headers, got := admin.doWithHeaders(http.MethodGet, "/commands/"+id+"/artifact", nil)
	if status != http.StatusOK || string(got) != "PK pretend zip" {
		t.Fatalf("download: %d %q", status, got)
	}
	if cd := headers.Get("Content-Disposition"); !strings.Contains(cd, "logs-PC-LOGS-") {
		t.Errorf("content-disposition = %q", cd)
	}
	entries, _ := a.Store.Q().ListAudit(context.Background(), 20)
	var audited bool
	for _, e := range entries {
		audited = audited || (e.Action == "command.artifact_downloaded" && e.TargetID == id)
	}
	if !audited {
		t.Error("the download wasn't audited")
	}

	// Another device can't upload to this command.
	_, other := enrollDevice(t, a, srv, "PC-OTHER")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/api/agent/v1/commands/"+id+"/artifact", bytes.NewReader([]byte("x")))
	res, err := other.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("another device's upload: %d", res.StatusCode)
	}
}

// TestWipeNeedsAPersonAndOneDevice: a wipe is refused to an API token, and
// for more than one device at once.
func TestWipeNeedsAPersonAndOneDevice(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	one, _ := enrollDevice(t, a, srv, "PC-ONE")
	two, _ := enrollDevice(t, a, srv, "PC-TWO")
	wipe := map[string]any{
		"device_ids": []string{one.String()}, "type": "wipe",
		"confirm_hostname": "PC-ONE", "reason": "decommissioned",
	}

	tok := makeToken(t, admin, "automation", store.RoleAdmin)
	if status, body := bearer(t, a, srv, tok.Token, http.MethodPost, "/commands", wipe); status != http.StatusForbidden {
		t.Fatalf("token wipe: %d %s", status, body)
	}
	both := map[string]any{
		"device_ids": []string{one.String(), two.String()}, "type": "wipe",
		"confirm_hostname": "PC-ONE", "reason": "decommissioned",
	}
	if status, _ := admin.do(http.MethodPost, "/commands", both); status != http.StatusBadRequest {
		t.Fatalf("two-device wipe: %d", status)
	}
	wrong := map[string]any{
		"device_ids": []string{one.String()}, "type": "wipe", "confirm_hostname": "PC-TWO", "reason": "x",
	}
	if status, _ := admin.do(http.MethodPost, "/commands", wrong); status != http.StatusBadRequest {
		t.Fatalf("mismatched hostname: %d", status)
	}
	if status, body := admin.do(http.MethodPost, "/commands", wipe); status != http.StatusCreated {
		t.Fatalf("wipe: %d %s", status, body)
	}
	// A token can still lock.
	lock := map[string]any{"device_ids": []string{one.String()}, "type": "lock"}
	if status, body := bearer(t, a, srv, tok.Token, http.MethodPost, "/commands", lock); status != http.StatusCreated {
		t.Fatalf("token lock: %d %s", status, body)
	}
}
