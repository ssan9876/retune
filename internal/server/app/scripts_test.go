package app_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type scriptResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CurrentVersion int    `json:"current_version"`
	Body           string `json:"body"`
}

// assignScript gives a script to the built-in group, which every device joins
// at enrollment.
func assignScript(t *testing.T, admin *adminClient, scriptID string, options map[string]any) {
	t.Helper()
	body := map[string]any{
		"item_kind": protocol.ItemKindScript, "item_id": scriptID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	}
	if options != nil {
		body["options"] = options
	}
	if status, out := admin.do(http.MethodPost, "/assignments", body); status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, out)
	}
}

func TestScriptDeploymentReachesTheAgent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-SCRIPTED")

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Install 7-Zip", "body": "winget install 7zip.7zip",
	})
	if status != http.StatusCreated {
		t.Fatalf("create script: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)

	assignScript(t, admin, script.ID, map[string]any{"frequency": "recurring", "interval_hours": 6})

	// Check-in names the script, its version, and the options.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 {
		t.Fatalf("want one assigned item, got %v", items)
	}
	if items[0].Kind != protocol.ItemKindScript || items[0].ID != script.ID {
		t.Fatalf("item = %+v", items[0])
	}
	if items[0].Version != 1 {
		t.Fatalf("version = %d, want 1", items[0].Version)
	}
	if len(items[0].Options) == 0 {
		t.Fatal("the options should travel with the item")
	}

	// The body is fetched separately, once per version.
	url := fmt.Sprintf("%s/api/agent/v1/scripts/%s/versions/1", srv.URL, script.ID)
	status, body = send(t, agent, http.MethodGet, url, nil)
	if status != http.StatusOK {
		t.Fatalf("fetch version: %d %s", status, body)
	}
	version := decodeJSON[protocol.ScriptVersionResponse](t, body)
	if version.Body != "winget install 7zip.7zip" || version.Hash == "" {
		t.Fatalf("version = %+v", version)
	}

	// Reporting a run moves the device's status and records history.
	status, body = send(t, agent, http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/scripts/%s/runs", srv.URL, script.ID),
		protocol.ScriptRun{
			Version: 1, Status: protocol.ResultSucceeded, Phase: protocol.PhaseScript,
			ExitCode: 0, Stdout: "installed",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report run: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/script/"+script.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	rollup := decodeJSON[struct {
		Rollup map[string]int `json:"rollup"`
	}](t, body).Rollup
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("rollup = %v", rollup)
	}

	status, body = admin.do(http.MethodGet, "/scripts/"+script.ID+"/runs", nil)
	if status != http.StatusOK {
		t.Fatalf("runs: %d %s", status, body)
	}
	runs := decodeJSON[struct {
		Items []struct {
			Hostname string `json:"hostname"`
			Stdout   string `json:"stdout"`
		} `json:"items"`
		Total int `json:"total"`
	}](t, body)
	if runs.Total != 1 || runs.Items[0].Hostname != "DESKTOP-SCRIPTED" || runs.Items[0].Stdout != "installed" {
		t.Fatalf("runs = %+v", runs)
	}
}

// A device may only read what it has been given.
func TestUnassignedScriptIsNotReadable(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-NOSY")

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Secret", "body": "Get-Secret",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)

	url := fmt.Sprintf("%s/api/agent/v1/scripts/%s/versions/1", srv.URL, script.ID)
	if status, _ := send(t, agent, http.MethodGet, url, nil); status != http.StatusNotFound {
		t.Fatalf("an unassigned script must not be readable, got %d", status)
	}

	// Once assigned, the same request succeeds.
	assignScript(t, admin, script.ID, nil)
	if status, body := send(t, agent, http.MethodGet, url, nil); status != http.StatusOK {
		t.Fatalf("an assigned script should be readable: %d %s", status, body)
	}
}

func TestEditingABodyMakesANewVersion(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-VERSIONED")

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Evolving", "body": "one",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)
	assignScript(t, admin, script.ID, nil)

	status, body = admin.do(http.MethodPost, "/scripts/"+script.ID, map[string]string{
		"name": "Evolving", "body": "two",
	})
	if status != http.StatusOK {
		t.Fatalf("update: %d %s", status, body)
	}
	if v := decodeJSON[scriptResp](t, body).CurrentVersion; v != 2 {
		t.Fatalf("current version = %d, want 2", v)
	}

	// The agent is now told version 2.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Version != 2 {
		t.Fatalf("items = %+v", items)
	}

	// And version 1 still says what it always said.
	url := fmt.Sprintf("%s/api/agent/v1/scripts/%s/versions/1", srv.URL, script.ID)
	status, body = send(t, agent, http.MethodGet, url, nil)
	if status != http.StatusOK {
		t.Fatalf("fetch v1: %d %s", status, body)
	}
	if got := decodeJSON[protocol.ScriptVersionResponse](t, body).Body; got != "one" {
		t.Fatalf("version 1 body = %q, versions must be immutable", got)
	}
}

func TestBadDeploymentOptionsAreRejected(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Picky", "body": "x",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": protocol.ItemKindScript, "item_id": script.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"frequency": "hourly"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("want 400 for a bad frequency, got %d %s", status, body)
	}
}

func TestScriptsAreClosedToReadOnlyAdmins(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/scripts", nil); status != http.StatusOK {
		t.Error("a read-only admin should be able to list scripts")
	}
	if status, _ := c.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Nope", "body": "x",
	}); status != http.StatusForbidden {
		t.Errorf("a read-only admin should not create scripts, got %d", status)
	}
}

// A deployment set to run as the signed-in user is stored, reported pending
// with a reason, and never sent to the agent as work.
func TestRunAsUserIsReportedPendingAndNotSent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-INTERACTIVE")

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Needs a user", "body": "Show-Dialog",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)
	assignScript(t, admin, script.ID, map[string]any{"run_as": "logged_in_user"})

	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	if items := decodeJSON[protocol.CheckinResponse](t, body).Items; len(items) != 0 {
		t.Fatalf("it must not be handed to the agent as work, got %+v", items)
	}

	status, body = admin.do(http.MethodGet, "/items/script/"+script.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[struct {
		Rollup map[string]int `json:"rollup"`
		Items  []struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"items"`
	}](t, body)
	if resp.Rollup[store.ItemPending] != 1 {
		t.Fatalf("it should be reported pending, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "not supported yet") {
		t.Errorf("the detail should say why, got %q", resp.Items[0].Detail)
	}
}
