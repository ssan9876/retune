package app_test

import (
	"net/http"
	"testing"

	"retune/internal/config"
	"retune/internal/server/store"
)

type approvalBody struct {
	Approval struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		Summary     string `json:"summary"`
		RequestedBy string `json:"requested_by"`
		DecidedBy   string `json:"decided_by"`
		Result      struct {
			Commands []struct {
				ID string `json:"id"`
			} `json:"commands"`
			Assignment *struct {
				ID   string `json:"id"`
				Mode string `json:"mode"`
			} `json:"assignment"`
			Error string `json:"error"`
		} `json:"result"`
	} `json:"approval"`
}

// TestTwoPersonApproval: with approvals on, a wipe - or code sent to more
// devices than the threshold - waits for a second administrator, and runs,
// as the person who asked for it, only once they approve.
func TestTwoPersonApproval(t *testing.T) {
	a, srv := newTestAppWith(t, func(c *config.Server) {
		c.Approvals = config.ApprovalsConfig{Required: true, DeviceThreshold: 1}
	})
	first := signedIn(t, a, srv, store.RoleAdmin)
	seedAdmin(t, a, "second@example.com", testPassword, store.RoleAdmin)
	second := newAdminClient(t, a, srv)
	if status, body := second.login("second@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	pc1, _ := enrollDevice(t, a, srv, "PC-APPR1")
	pc2, _ := enrollDevice(t, a, srv, "PC-APPR2")
	commandsFor := func(id string) int {
		t.Helper()
		status, body := first.do(http.MethodGet, "/commands?device_id="+id, nil)
		if status != http.StatusOK {
			t.Fatalf("list commands: %d %s", status, body)
		}
		return decodeJSON[struct {
			Total int `json:"total"`
		}](t, body).Total
	}
	decide := func(c *adminClient, id, verb string, want int) approvalBody {
		t.Helper()
		status, body := c.do(http.MethodPost, "/approvals/"+id+"/"+verb, map[string]any{"reason": "checked"})
		if status != want {
			t.Fatalf("%s %s: %d %s, want %d", verb, id, status, body, want)
		}
		if status != http.StatusOK {
			return approvalBody{}
		}
		return decodeJSON[approvalBody](t, body)
	}

	// A wipe is checked in full before it is held: a wrong hostname is
	// refused now, not after someone approves it.
	wipe := map[string]any{"device_ids": []string{pc1.String()}, "type": "wipe", "confirm_hostname": "PC-WRONG", "reason": "stolen"}
	if status, _ := first.do(http.MethodPost, "/commands", wipe); status != http.StatusBadRequest {
		t.Fatalf("wipe with the wrong hostname: %d, want 400", status)
	}
	wipe["confirm_hostname"] = "PC-APPR1"
	status, body := first.do(http.MethodPost, "/commands", wipe)
	if status != http.StatusAccepted {
		t.Fatalf("wipe: %d %s, want 202", status, body)
	}
	held := decodeJSON[approvalBody](t, body).Approval
	if held.Status != store.ApprovalPending || held.Kind != store.ApprovalCommand || held.RequestedBy != "ops@example.com" {
		t.Fatalf("held = %+v", held)
	}
	if n := commandsFor(pc1.String()); n != 0 {
		t.Fatalf("%d commands queued before approval", n)
	}

	// Not by the person who asked.
	decide(first, held.ID, "approve", http.StatusForbidden)
	status, body = second.do(http.MethodGet, "/approvals?status=pending", nil)
	if status != http.StatusOK || decodeJSON[struct {
		Total int `json:"total"`
	}](t, body).Total != 1 {
		t.Fatalf("pending: %d %s", status, body)
	}
	done := decide(second, held.ID, "approve", http.StatusOK).Approval
	if done.Status != store.ApprovalApproved || done.DecidedBy != "second@example.com" || len(done.Result.Commands) != 1 {
		t.Fatalf("approved = %+v", done)
	}
	status, body = first.do(http.MethodGet, "/commands/"+done.Result.Commands[0].ID, nil)
	if status != http.StatusOK {
		t.Fatalf("get command: %d %s", status, body)
	}
	if cmd := decodeJSON[struct {
		Command struct {
			Type      string `json:"type"`
			CreatedBy string `json:"created_by"`
		} `json:"command"`
	}](t, body).Command; cmd.Type != "wipe" || cmd.CreatedBy != "ops@example.com" {
		t.Fatalf("queued = %+v", cmd)
	}
	// Once only.
	decide(second, held.ID, "approve", http.StatusConflict)
	decide(second, held.ID, "reject", http.StatusConflict)

	// PowerShell to as many devices as the threshold goes straight out; to
	// more, it waits. The requester can withdraw their own request.
	both := []string{pc1.String(), pc2.String()}
	if status, body := first.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": both[:1], "type": "run_powershell", "script": "Get-Date",
	}); status != http.StatusCreated {
		t.Fatalf("run_powershell to one: %d %s", status, body)
	}
	status, body = first.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": both, "type": "run_powershell", "script": "Get-Date",
	})
	if status != http.StatusAccepted {
		t.Fatalf("run_powershell to two: %d %s", status, body)
	}
	ps := decodeJSON[approvalBody](t, body).Approval
	if ps.Summary != "run_powershell on 2 devices" {
		t.Fatalf("summary = %q", ps.Summary)
	}
	if got := decide(first, ps.ID, "reject", http.StatusOK).Approval; got.Status != store.ApprovalRejected {
		t.Fatalf("withdrawn = %+v", got)
	}
	if n := commandsFor(pc2.String()); n != 0 {
		t.Fatalf("%d commands on PC-APPR2 after a rejection", n)
	}

	// A token's requests belong to the admin who made it.
	tok := makeToken(t, first, "automation", store.RoleAdmin)
	status, body = bearer(t, a, srv, tok.Token, http.MethodPost, "/commands",
		map[string]any{"device_ids": both, "type": "run_powershell", "script": "Get-Date"})
	if status != http.StatusAccepted {
		t.Fatalf("token run_powershell: %d %s", status, body)
	}
	byToken := decodeJSON[approvalBody](t, body).Approval
	decide(first, byToken.ID, "approve", http.StatusForbidden)
	// Nor can a token decide anything.
	if status, _ := bearer(t, a, srv, tok.Token, http.MethodPost, "/approvals/"+byToken.ID+"/approve", map[string]any{}); status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Fatalf("token approving: %d", status)
	}
	if got := decide(second, byToken.ID, "approve", http.StatusOK).Approval; got.Status != store.ApprovalApproved || len(got.Result.Commands) != 2 {
		t.Fatalf("token request approved = %+v", got)
	}

	// Anything assigned to All devices waits; an exclusion doesn't.
	status, body = first.do(http.MethodPost, "/scripts", map[string]any{"name": "Clean temp", "body": "Get-Date"})
	if status != http.StatusCreated {
		t.Fatalf("create script: %d %s", status, body)
	}
	scriptID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	assign := map[string]any{"item_kind": "script", "item_id": scriptID, "group_id": store.BuiltinGroupID.String(), "mode": "include"}
	status, body = first.do(http.MethodPost, "/assignments", assign)
	if status != http.StatusAccepted {
		t.Fatalf("assign to all devices: %d %s", status, body)
	}
	assignment := decodeJSON[approvalBody](t, body).Approval
	assignments := func() int {
		t.Helper()
		status, body := first.do(http.MethodGet, "/assignments?item_kind=script&item_id="+scriptID, nil)
		if status != http.StatusOK {
			t.Fatalf("list assignments: %d %s", status, body)
		}
		return len(decodeJSON[struct {
			Items []any `json:"items"`
		}](t, body).Items)
	}
	if n := assignments(); n != 0 {
		t.Fatalf("%d assignments before approval", n)
	}
	got := decide(second, assignment.ID, "approve", http.StatusOK).Approval
	if got.Status != store.ApprovalApproved || got.Result.Assignment == nil || got.Result.Assignment.Mode != "include" {
		t.Fatalf("assignment approved = %+v", got)
	}
	if n := assignments(); n != 1 {
		t.Fatalf("%d assignments after approval", n)
	}
	assign["mode"] = "exclude"
	if status, body := first.do(http.MethodPost, "/assignments", assign); status != http.StatusCreated {
		t.Fatalf("exclude: %d %s", status, body)
	}

	// An approved request that can no longer be done is marked failed, with
	// why.
	pc3, _ := enrollDevice(t, a, srv, "PC-APPR3")
	status, body = first.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{pc3.String()}, "type": "wipe", "confirm_hostname": "PC-APPR3", "reason": "leaver",
	})
	if status != http.StatusAccepted {
		t.Fatalf("wipe PC-APPR3: %d %s", status, body)
	}
	late := decodeJSON[approvalBody](t, body).Approval
	if status, body := first.do(http.MethodPost, "/devices/"+pc3.String()+"/retire", nil); status != http.StatusNoContent {
		t.Fatalf("retire: %d %s", status, body)
	}
	if got := decide(second, late.ID, "approve", http.StatusOK).Approval; got.Status != store.ApprovalFailed || got.Result.Error == "" {
		t.Fatalf("late approval = %+v", got)
	}
}

// TestApprovalsOff: without APPROVALS_REQUIRED nothing waits.
func TestApprovalsOff(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	id, _ := enrollDevice(t, a, srv, "PC-NOAPPR")
	if status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{id.String()}, "type": "wipe", "confirm_hostname": "PC-NOAPPR", "reason": "x",
	}); status != http.StatusCreated {
		t.Fatalf("wipe: %d %s", status, body)
	}
}
