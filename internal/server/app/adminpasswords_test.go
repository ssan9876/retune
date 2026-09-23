package app_test

import (
	"context"
	"net/http"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type adminPasswordItem struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	State   string `json:"state"`
}

// rotateOnce drives one rotation through the agent API the way an agent
// does: check in, start, escrow, then report status. It returns the
// command's ID.
func rotateOnce(t *testing.T, admin *adminClient, agent *http.Client, base, deviceID, password, status string) string {
	t.Helper()
	code, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{deviceID}, "type": "rotate_local_admin_password",
	})
	if code != http.StatusCreated {
		t.Fatalf("queue: %d %s", code, body)
	}
	id := decodeJSON[queuedResp](t, body).Commands[0].ID
	send(t, agent, http.MethodPost, base+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if code, body := send(t, agent, http.MethodPost, base+"/api/agent/v1/commands/"+id+"/start", nil); code != http.StatusNoContent {
		t.Fatalf("start: %d %s", code, body)
	}
	if code, body := send(t, agent, http.MethodPost, base+"/api/agent/v1/admin-passwords", protocol.AdminPasswordEscrowRequest{
		CommandID: id, Account: "Administrator", Password: password,
	}); code != http.StatusNoContent {
		t.Fatalf("escrow: %d %s", code, body)
	}
	if code, body := send(t, agent, http.MethodPost, base+"/api/agent/v1/commands/"+id+"/result", protocol.CommandResult{
		Status: status,
	}); code != http.StatusNoContent {
		t.Fatalf("result: %d %s", code, body)
	}
	return id
}

func listPasswords(t *testing.T, admin *adminClient, deviceID string) []adminPasswordItem {
	t.Helper()
	code, body := admin.do(http.MethodGet, "/devices/"+deviceID+"/admin-passwords", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	return decodeJSON[struct {
		Items []adminPasswordItem `json:"items"`
	}](t, body).Items
}

func TestLocalAdminPasswordRotation(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	id, agent := enrollDevice(t, a, srv, "PC-LAPS")
	device := id.String()

	rotateOnce(t, admin, agent, srv.URL, device, "First-Password-Long-Enough-1", protocol.ResultSucceeded)
	items := listPasswords(t, admin, device)
	if len(items) != 1 || items[0].State != store.AdminPasswordActive || items[0].Account != "Administrator" {
		t.Fatalf("after one rotation: %+v", items)
	}
	first := items[0].ID

	// A second rotation supersedes the first; a failed third is abandoned
	// and leaves the second active.
	rotateOnce(t, admin, agent, srv.URL, device, "Second-Password-Long-Enough-2", protocol.ResultSucceeded)
	rotateOnce(t, admin, agent, srv.URL, device, "Third-Password-Long-Enough-33", protocol.ResultFailed)
	states := map[string]int{}
	for _, it := range listPasswords(t, admin, device) {
		states[it.State]++
	}
	if states[store.AdminPasswordActive] != 1 || states[store.AdminPasswordSuperseded] != 1 || states[store.AdminPasswordAbandoned] != 1 {
		t.Fatalf("states = %v", states)
	}

	// Revealing needs a reason, and returns the password.
	if code, _ := admin.do(http.MethodPost, "/admin-passwords/"+first+"/reveal", map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("reveal without a reason: %d", code)
	}
	code, body := admin.do(http.MethodPost, "/admin-passwords/"+first+"/reveal", map[string]any{"reason": "ticket 42"})
	if code != http.StatusOK {
		t.Fatalf("reveal: %d %s", code, body)
	}
	if got := decodeJSON[struct {
		Password string `json:"password"`
	}](t, body).Password; got != "First-Password-Long-Enough-1" {
		t.Fatalf("revealed %q", got)
	}
	entries, _ := a.Store.Q().ListAudit(context.Background(), 30)
	var audited bool
	for _, e := range entries {
		audited = audited || (e.Action == "local_admin_password.revealed" && e.Details["reason"] == "ticket 42")
		if e.Action == "local_admin_password.escrowed" {
			for _, v := range e.Details {
				if s, ok := v.(string); ok && len(s) > 20 && s[:5] == "First" {
					t.Fatal("the password is in the audit log")
				}
			}
		}
	}
	if !audited {
		t.Error("the reveal wasn't audited")
	}

	// Read-only admins and API tokens can't reveal.
	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if code, _ := ro.do(http.MethodPost, "/admin-passwords/"+first+"/reveal", map[string]any{"reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("read-only reveal: %d", code)
	}
	tok := makeToken(t, admin, "script", store.RoleAdmin)
	if code, _ := bearer(t, a, srv, tok.Token, http.MethodPost, "/admin-passwords/"+first+"/reveal", map[string]any{"reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("token reveal: %d", code)
	}
}

func TestAdminPasswordEscrowIsGated(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	id, agent := enrollDevice(t, a, srv, "PC-ONE")
	_, other := enrollDevice(t, a, srv, "PC-TWO")

	code, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{id.String()}, "type": "rotate_local_admin_password", "length": 32,
	})
	if code != http.StatusCreated {
		t.Fatalf("queue: %d %s", code, body)
	}
	cmd := decodeJSON[queuedResp](t, body).Commands[0].ID
	escrow := func(c *http.Client, commandID, password string) int {
		code, _ := send(t, c, http.MethodPost, srv.URL+"/api/agent/v1/admin-passwords", protocol.AdminPasswordEscrowRequest{
			CommandID: commandID, Account: "Administrator", Password: password,
		})
		return code
	}
	good := "A-Long-Enough-Password-123"
	if code := escrow(agent, cmd, good); code != http.StatusConflict {
		t.Fatalf("before start: %d", code)
	}
	send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "1.0.0"})
	send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/commands/"+cmd+"/start", nil)
	if code := escrow(other, cmd, good); code != http.StatusNotFound {
		t.Fatalf("another device: %d", code)
	}
	if code := escrow(agent, cmd, "short"); code != http.StatusBadRequest {
		t.Fatalf("short password: %d", code)
	}
	if code := escrow(agent, cmd, good); code != http.StatusNoContent {
		t.Fatalf("escrow: %d", code)
	}
	items := listPasswords(t, admin, id.String())
	if len(items) != 1 || items[0].State != store.AdminPasswordPending {
		t.Fatalf("before the result: %+v", items)
	}
	if code, _ := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{id.String()}, "type": "rotate_local_admin_password", "length": 12,
	}); code != http.StatusBadRequest {
		t.Fatalf("length 12: %d", code)
	}
}
