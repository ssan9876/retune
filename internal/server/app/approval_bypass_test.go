package app_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/store"
)

// approvalsApp is a server with two-person approval on and a threshold of one
// device, with two administrators: first asks, second approves.
func approvalsApp(t *testing.T) (a *app.App, srv *httptest.Server, first, second *adminClient) {
	t.Helper()
	a, srv = newTestAppWith(t, func(c *config.Server) {
		c.Approvals = config.ApprovalsConfig{Required: true, DeviceThreshold: 1}
	})
	first = signedIn(t, a, srv, store.RoleAdmin)
	seedAdmin(t, a, "second@example.com", testPassword, store.RoleAdmin)
	second = newAdminClient(t, a, srv)
	if status, body := second.login("second@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	return a, srv, first, second
}

func mustStatus(t *testing.T, what string, want, status int, body []byte) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: %d %s, want %d", what, status, body, want)
	}
}

func approve(t *testing.T, c *adminClient, id string) approvalBody {
	t.Helper()
	status, body := c.do(http.MethodPost, "/approvals/"+id+"/approve", map[string]any{})
	mustStatus(t, "approve "+id, http.StatusOK, status, body)
	return decodeJSON[approvalBody](t, body)
}

// A new version of a script already sent to many devices waits for a second
// administrator, and until then devices keep - and can only fetch - the
// version that was approved.
func TestApprovalHoldsNewVersionsOfWidelyAssignedScripts(t *testing.T) {
	a, srv, first, second := approvalsApp(t)
	_, agent := enrollDevice(t, a, srv, "PC-VERSION")

	checkinVersion := func() int {
		t.Helper()
		status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "1.0.0"})
		mustStatus(t, "checkin", http.StatusOK, status, body)
		items := decodeJSON[protocol.CheckinResponse](t, body).Items
		if len(items) != 1 {
			t.Fatalf("items = %v", items)
		}
		return items[0].Version
	}
	fetch := func(scriptID string, version string) int {
		t.Helper()
		status, _ := send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/scripts/"+scriptID+"/versions/"+version, nil)
		return status
	}

	status, body := first.do(http.MethodPost, "/scripts", map[string]any{"name": "Tidy", "body": "Get-Date"})
	mustStatus(t, "create script", http.StatusCreated, status, body)
	scriptID := decodeJSON[scriptResp](t, body).ID

	// Before it is assigned anywhere, an edit is nobody's business.
	status, body = first.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{"name": "Tidy", "body": "Get-Date # 2"})
	mustStatus(t, "unassigned edit", http.StatusOK, status, body)

	status, body = first.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "script", "item_id": scriptID, "group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	mustStatus(t, "assign to all devices", http.StatusAccepted, status, body)
	approve(t, second, decodeJSON[approvalBody](t, body).Approval.ID)
	if v := checkinVersion(); v != 2 {
		t.Fatalf("checkin version = %d, want 2", v)
	}

	// Now the code can't change without a second administrator.
	status, body = first.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{"name": "Tidy", "body": "Remove-Item C:\\ -Recurse"})
	mustStatus(t, "edit", http.StatusAccepted, status, body)
	held := decodeJSON[approvalBody](t, body).Approval
	if held.Kind != store.ApprovalVersion || !strings.Contains(held.Summary, "version 3") {
		t.Fatalf("held = %+v", held)
	}
	if v := checkinVersion(); v != 2 {
		t.Fatalf("a held version reached check-in: %d", v)
	}
	if s := fetch(scriptID, "3"); s != http.StatusNotFound {
		t.Fatalf("fetching the held version: %d, want 404", s)
	}
	if s := fetch(scriptID, "2"); s != http.StatusOK {
		t.Fatalf("fetching the approved version: %d", s)
	}
	// The editor still opens the approved code.
	status, body = first.do(http.MethodGet, "/scripts/"+scriptID, nil)
	mustStatus(t, "get script", http.StatusOK, status, body)
	if got := decodeJSON[struct {
		Body           string `json:"body"`
		CurrentVersion int    `json:"current_version"`
	}](t, body); got.CurrentVersion != 2 || got.Body != "Get-Date # 2" {
		t.Fatalf("script = %+v", got)
	}

	// Renaming changes no code, so it doesn't wait.
	status, body = first.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{"name": "Tidy up", "body": "Get-Date # 2"})
	mustStatus(t, "rename", http.StatusOK, status, body)

	// A second edit while the first waits is numbered after it.
	status, body = first.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{"name": "Tidy up", "body": "Get-Date # 4"})
	mustStatus(t, "second edit", http.StatusAccepted, status, body)
	later := decodeJSON[approvalBody](t, body).Approval

	done := approve(t, second, later.ID).Approval
	if done.Status != store.ApprovalApproved {
		t.Fatalf("approved = %+v", done)
	}
	if v := checkinVersion(); v != 4 {
		t.Fatalf("checkin version after approval = %d, want 4", v)
	}
	if s := fetch(scriptID, "4"); s != http.StatusOK {
		t.Fatalf("fetching the approved version: %d", s)
	}
	// Approving the older one now would roll devices back, so it fails.
	if got := approve(t, second, held.ID).Approval; got.Status != store.ApprovalFailed || got.Result.Error == "" {
		t.Fatalf("superseded approval = %+v", got)
	}
	if v := checkinVersion(); v != 4 {
		t.Fatalf("checkin version = %d after a superseded approval", v)
	}
}

// A held profile edit is stored sealed: the approval shows no secret.
func TestApprovalHoldsProfileVersionsWithoutExposingSecrets(t *testing.T) {
	a, srv, first, second := approvalsApp(t)
	enrollDevice(t, a, srv, "PC-PROFILE")
	const secret = "correct horse battery"

	status, body := first.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Office Wi-Fi", "settings": []map[string]any{{"kind": "service", "name": "Spooler", "state": "stopped"}},
	})
	mustStatus(t, "create profile", http.StatusCreated, status, body)
	profileID := decodeJSON[profileResp](t, body).ID
	status, body = first.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "profile", "item_id": profileID, "group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	mustStatus(t, "assign", http.StatusAccepted, status, body)
	approve(t, second, decodeJSON[approvalBody](t, body).Approval.ID)

	status, body = first.do(http.MethodPost, "/profiles/"+profileID, map[string]any{
		"name": "Office Wi-Fi", "settings": []map[string]any{
			{"kind": "wifi", "ssid": "Contoso Corp", "security": "wpa2_personal", "passphrase": secret},
		},
	})
	mustStatus(t, "edit", http.StatusAccepted, status, body)
	if strings.Contains(string(body), secret) {
		t.Fatalf("the held request shows the passphrase: %s", body)
	}
	held := decodeJSON[approvalBody](t, body).Approval
	status, body = second.do(http.MethodGet, "/approvals?status=pending", nil)
	mustStatus(t, "list approvals", http.StatusOK, status, body)
	if strings.Contains(string(body), secret) {
		t.Fatalf("the approvals list shows the passphrase: %s", body)
	}
	status, body = first.do(http.MethodGet, "/profiles/"+profileID, nil)
	mustStatus(t, "get profile", http.StatusOK, status, body)
	if v := decodeJSON[profileResp](t, body).CurrentVersion; v != 1 {
		t.Fatalf("current version before approval = %d", v)
	}
	approve(t, second, held.ID)
	status, body = first.do(http.MethodGet, "/profiles/"+profileID, nil)
	mustStatus(t, "get profile", http.StatusOK, status, body)
	if v := decodeJSON[profileResp](t, body).CurrentVersion; v != 2 {
		t.Fatalf("current version after approval = %d", v)
	}
}

// An app edit waits the same way.
func TestApprovalHoldsAppVersions(t *testing.T) {
	a, srv, first, second := approvalsApp(t)
	enrollDevice(t, a, srv, "PC-APP")

	status, body := first.do(http.MethodPost, "/apps", map[string]any{"name": "7-Zip", "package_id": "7zip.7zip"})
	mustStatus(t, "create app", http.StatusCreated, status, body)
	appID := decodeJSON[appResp](t, body).ID
	status, body = first.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": appID, "group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	mustStatus(t, "assign", http.StatusAccepted, status, body)
	approve(t, second, decodeJSON[approvalBody](t, body).Approval.ID)

	status, body = first.do(http.MethodPost, "/apps/"+appID, map[string]any{"name": "7-Zip", "package_id": "7zip.7zip", "install_args": "/S"})
	mustStatus(t, "edit", http.StatusAccepted, status, body)
	done := approve(t, second, decodeJSON[approvalBody](t, body).Approval.ID).Approval
	if done.Status != store.ApprovalApproved {
		t.Fatalf("approved = %+v", done)
	}
}

// Growing a static group that has code assigned waits once it would hold
// more devices than the threshold; changing a dynamic group's rule under
// its assignments always waits.
func TestApprovalHoldsGroupsGrowingUnderAssignments(t *testing.T) {
	a, srv, first, second := approvalsApp(t)
	pc1, _ := enrollDevice(t, a, srv, "PC-GROW1")
	pc2, _ := enrollDevice(t, a, srv, "PC-GROW2")
	members := func(groupID string) int {
		t.Helper()
		status, body := first.do(http.MethodGet, "/groups/"+groupID+"/members", nil)
		mustStatus(t, "members", http.StatusOK, status, body)
		return decodeJSON[struct {
			Total int `json:"total"`
		}](t, body).Total
	}

	status, body := first.do(http.MethodPost, "/scripts", map[string]any{"name": "Pilot", "body": "Get-Date"})
	mustStatus(t, "create script", http.StatusCreated, status, body)
	scriptID := decodeJSON[scriptResp](t, body).ID

	// A group with nothing assigned grows freely.
	status, body = first.do(http.MethodPost, "/groups", map[string]any{"name": "Loose", "kind": "static"})
	mustStatus(t, "create group", http.StatusCreated, status, body)
	loose := decodeJSON[groupResp](t, body).ID
	for _, d := range []string{pc1.String(), pc2.String()} {
		status, body = first.do(http.MethodPost, "/groups/"+loose+"/members", map[string]any{"device_id": d})
		mustStatus(t, "add to a group with nothing assigned", http.StatusNoContent, status, body)
	}

	// An empty static group takes an assignment without approval...
	status, body = first.do(http.MethodPost, "/groups", map[string]any{"name": "Pilot ring", "kind": "static"})
	mustStatus(t, "create group", http.StatusCreated, status, body)
	ring := decodeJSON[groupResp](t, body).ID
	status, body = first.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "script", "item_id": scriptID, "group_id": ring, "mode": "include",
	})
	mustStatus(t, "assign to an empty group", http.StatusCreated, status, body)
	// ...and one device, up to the threshold...
	status, body = first.do(http.MethodPost, "/groups/"+ring+"/members", map[string]any{"device_id": pc1.String()})
	mustStatus(t, "first member", http.StatusNoContent, status, body)
	// ...but not a second.
	status, body = first.do(http.MethodPost, "/groups/"+ring+"/members", map[string]any{"device_id": pc2.String()})
	mustStatus(t, "second member", http.StatusAccepted, status, body)
	held := decodeJSON[approvalBody](t, body).Approval
	if held.Kind != store.ApprovalGroupMember || !strings.Contains(held.Summary, "PC-GROW2") {
		t.Fatalf("held = %+v", held)
	}
	if n := members(ring); n != 1 {
		t.Fatalf("%d members before approval", n)
	}
	// Adding a device that is already there changes nothing, so it doesn't wait.
	status, body = first.do(http.MethodPost, "/groups/"+ring+"/members", map[string]any{"device_id": pc1.String()})
	mustStatus(t, "existing member", http.StatusNoContent, status, body)
	if got := approve(t, second, held.ID).Approval; got.Status != store.ApprovalApproved {
		t.Fatalf("approved = %+v", got)
	}
	if n := members(ring); n != 2 {
		t.Fatalf("%d members after approval", n)
	}
	// A device that doesn't exist is refused now, not after approval.
	status, body = first.do(http.MethodPost, "/groups/"+ring+"/members", map[string]any{"device_id": "01900000-0000-7000-8000-000000000000"})
	mustStatus(t, "unknown device", http.StatusNotFound, status, body)

	// A dynamic group's rule decides who its code reaches.
	status, body = first.do(http.MethodPost, "/groups", map[string]any{"name": "Grow", "kind": "dynamic", "rule": "hostname = 'PC-GROW1'"})
	mustStatus(t, "create dynamic group", http.StatusCreated, status, body)
	grow := decodeJSON[groupResp](t, body).ID
	status, body = first.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "script", "item_id": scriptID, "group_id": grow, "mode": "include",
	})
	mustStatus(t, "assign to a dynamic group", http.StatusAccepted, status, body)
	approve(t, second, decodeJSON[approvalBody](t, body).Approval.ID)

	status, body = first.do(http.MethodPost, "/groups/"+grow, map[string]any{"name": "Grow", "rule": "hostname LIKE 'PC-%'"})
	mustStatus(t, "change the rule", http.StatusAccepted, status, body)
	ruleChange := decodeJSON[approvalBody](t, body).Approval
	if ruleChange.Kind != store.ApprovalGroupRule {
		t.Fatalf("held = %+v", ruleChange)
	}
	if n := members(grow); n != 1 {
		t.Fatalf("%d members before the rule change is approved", n)
	}
	// A rule that doesn't parse is refused now.
	status, body = first.do(http.MethodPost, "/groups/"+grow, map[string]any{"name": "Grow", "rule": "hostname LIKE"})
	mustStatus(t, "bad rule", http.StatusBadRequest, status, body)
	// Renaming keeps the rule, so it doesn't wait.
	status, body = first.do(http.MethodPost, "/groups/"+grow, map[string]any{"name": "Growing", "rule": "hostname = 'PC-GROW1'"})
	mustStatus(t, "rename", http.StatusOK, status, body)

	approve(t, second, ruleChange.ID)
	if n := members(grow); n != 2 {
		t.Fatalf("%d members after the rule change", n)
	}
}

// Ad-hoc PowerShell is counted per administrator over the last hour, so
// splitting a request doesn't get it past the threshold.
func TestApprovalCountsPowerShellPerAdminOverTheLastHour(t *testing.T) {
	a, srv, first, second := approvalsApp(t)
	pc1, _ := enrollDevice(t, a, srv, "PC-PS1")
	pc2, _ := enrollDevice(t, a, srv, "PC-PS2")
	run := func(c *adminClient, device string) (int, []byte) {
		return c.do(http.MethodPost, "/commands", map[string]any{
			"device_ids": []string{device}, "type": "run_powershell", "script": "Get-Date",
		})
	}

	status, body := run(first, pc1.String())
	mustStatus(t, "first device", http.StatusCreated, status, body)
	// The same device again is still one device.
	status, body = run(first, pc1.String())
	mustStatus(t, "same device again", http.StatusCreated, status, body)
	// A second device, in a request of its own, is two within the hour.
	status, body = run(first, pc2.String())
	mustStatus(t, "second device", http.StatusAccepted, status, body)
	held := decodeJSON[approvalBody](t, body).Approval
	if held.Summary != "run_powershell on 1 device (2 in the last hour)" {
		t.Fatalf("summary = %q", held.Summary)
	}
	// Someone else's count is their own.
	status, body = run(second, pc2.String())
	mustStatus(t, "another administrator", http.StatusCreated, status, body)

	// What a second administrator approved doesn't count against the next
	// request.
	approve(t, second, held.ID)
	status, body = run(first, pc1.String())
	mustStatus(t, "after approval", http.StatusCreated, status, body)
}
