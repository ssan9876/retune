package app_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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

// The upsert behind reassignment is not app-specific: a script assigned
// again to the same group with different deployment options replaces those
// options in place, the same as an app's intent does.
func TestReassigningAScriptReplacesItsOptions(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Held item", "body": "echo hi",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": protocol.ItemKindScript, "item_id": script.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"frequency": "once"},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign once: %d %s", status, body)
	}
	first := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body)

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": protocol.ItemKindScript, "item_id": script.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"frequency": "recurring", "interval_hours": 6},
	})
	if status != http.StatusCreated {
		t.Fatalf("reassign as recurring: %d %s", status, body)
	}
	second := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body)
	if second.ID != first.ID {
		t.Errorf("a replacement keeps the original row's id, got %q want %q", second.ID, first.ID)
	}
	if !strings.Contains(string(body), `"frequency":"recurring"`) {
		t.Errorf("the stored options should now say recurring, got %s", body)
	}

	status, body = admin.do(http.MethodGet, "/assignments?item_kind="+protocol.ItemKindScript+"&item_id="+script.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("list assignments: %d %s", status, body)
	}
	list := decodeJSON[struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}](t, body)
	if len(list.Items) != 1 {
		t.Fatalf("reassigning must replace the row, not add one, got %d assignments", len(list.Items))
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

// A deployment set to run as the signed-in user reaches the agent either way.
// With nobody signed in the server reports it pending, from what the check-in
// told it; once somebody signs in it is ordinary work.
func TestRunAsUserIsPendingUntilSomebodySignsIn(t *testing.T) {
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

	// Nobody is signed in.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	// The agent still receives it, so it can run the moment somebody signs in
	// between check-ins.
	if items := decodeJSON[protocol.CheckinResponse](t, body).Items; len(items) != 1 {
		t.Fatalf("the agent should receive it, got %+v", items)
	}

	resp := itemStatus(t, admin, script.ID)
	if resp.Rollup[store.ItemPending] != 1 {
		t.Fatalf("it should be reported pending, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "sign in") {
		t.Errorf("the detail should say why, got %q", resp.Items[0].Detail)
	}

	// Somebody signs in, so the server stops calling it pending on its own,
	// and the run the agent reports settles it.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0", LoggedInUser: `CORP\ada`})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	status, body = send(t, agent, http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/scripts/%s/runs", srv.URL, script.ID),
		protocol.ScriptRun{
			Version: 1, Status: protocol.ResultSucceeded, Phase: protocol.PhaseScript,
			ExitCode: 0, Stdout: "shown",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report run: %d %s", status, body)
	}
	resp = itemStatus(t, admin, script.ID)
	if resp.Rollup[store.ItemPending] != 0 || resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("it should have succeeded, got %v", resp.Rollup)
	}
}

// itemStatusResp is the part of the per-device status these tests read.
type itemStatusResp struct {
	Rollup map[string]int `json:"rollup"`
	Items  []struct {
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"items"`
}

func itemStatus(t *testing.T, admin *adminClient, scriptID string) itemStatusResp {
	t.Helper()
	status, body := admin.do(http.MethodGet, "/items/script/"+scriptID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	return decodeJSON[itemStatusResp](t, body)
}

// The per-device status says which version it refers to, so "succeeded" is
// never ambiguous after an edit.
func TestItemStatusCarriesTheVersion(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-VERSIONSTATUS")

	status, body := admin.do(http.MethodPost, "/scripts", map[string]string{
		"name": "Versioned status", "body": "one",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	script := decodeJSON[scriptResp](t, body)
	assignScript(t, admin, script.ID, nil)

	if status, body := admin.do(http.MethodPost, "/scripts/"+script.ID, map[string]string{
		"name": "Versioned status", "body": "two",
	}); status != http.StatusOK {
		t.Fatalf("update: %d %s", status, body)
	}

	status, body = send(t, agent, http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/scripts/%s/runs", srv.URL, script.ID),
		protocol.ScriptRun{
			Version: 2, Status: protocol.ResultSucceeded, Phase: protocol.PhaseScript,
		})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/script/"+script.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[struct {
		Items []struct {
			Status  string `json:"status"`
			Version int    `json:"version"`
		} `json:"items"`
	}](t, body)
	if len(resp.Items) != 1 || resp.Items[0].Version != 2 {
		t.Fatalf("the status should name version 2, got %+v", resp.Items)
	}
}

// An item of a kind this server does not implement is never handed to an
// agent. There is no endpoint to fetch its content from and no version to
// fetch, so sending it could only confuse.
func TestCheckinDropsAnUnknownItemKind(t *testing.T) {
	a, srv := newTestApp(t)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UNKNOWNKIND")

	// Written straight to the store, because the admin API now refuses it.
	_, err := a.Store.Q().CreateAssignment(context.Background(), store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: "widget", ItemID: uuid.Must(uuid.NewV7()),
		GroupID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		Mode:    store.ModeInclude, CreatedAt: time.Now(), CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	if items := decodeJSON[protocol.CheckinResponse](t, body).Items; len(items) != 0 {
		t.Fatalf("a kind nothing implements must not be sent, got %+v", items)
	}
}
