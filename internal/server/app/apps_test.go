package app_test

import (
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type appResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PackageID      string `json:"package_id"`
	PinnedVersion  string `json:"pinned_version"`
	Scope          string `json:"scope"`
	CurrentVersion int    `json:"current_version"`
}

func TestAppLifecycle(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "description": "archiver", "package_id": "7zip.7zip",
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	app := decodeJSON[appResp](t, body)
	if app.Scope != "machine" || app.CurrentVersion != 1 {
		t.Fatalf("a new app should default to machine scope at version 1, got %+v", app)
	}

	status, body = admin.do(http.MethodGet, "/apps/"+app.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	if got := decodeJSON[appResp](t, body); got.PackageID != "7zip.7zip" {
		t.Errorf("the editor needs the package id, got %+v", got)
	}

	status, body = admin.do(http.MethodDelete, "/apps/"+app.ID, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
}

// An app assignment carries an intent, and it is validated at the API rather
// than left for the agent to puzzle over.
func TestAppAssignmentIntent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"intent": "uninstall"},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"intent":"uninstall"`) {
		t.Errorf("the stored options should keep the intent, got %s", body)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"intent": "upgrade"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("an intent nobody implements should be refused, got %d %s", status, body)
	}
}

// A device may only read what it has been given, and an app it was never
// assigned is a 404 -- the same answer as one that does not exist, which is
// all an agent needs to know.
func TestAgentReadsOnlyAssignedApps(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-APPS")

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)

	status, _ := send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/versions/1", nil)
	if status != http.StatusNotFound {
		t.Fatalf("an unassigned app must not be readable, got %d", status)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/versions/1", nil)
	if status != http.StatusOK {
		t.Fatalf("version: %d %s", status, body)
	}
	if got := decodeJSON[protocol.AppVersionResponse](t, body); got.PackageID != "7zip.7zip" {
		t.Errorf("version = %+v", got)
	}
}

// Check-in offers the app with its current version, and a reported result
// settles the device's status.
func TestAppReachesTheAgentAndReportsBack(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-APPS")

	_, body := admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip",
	})
	app := decodeJSON[appResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": app.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindApp || items[0].Version != 1 {
		t.Fatalf("the app should be offered at version 1, got %+v", items)
	}

	status, body = send(t, agent, http.MethodPost,
		srv.URL+"/api/agent/v1/apps/"+app.ID+"/result",
		protocol.AppResult{
			Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultSucceeded,
			InstalledVersion: "26.03",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/app/"+app.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "26.03") {
		t.Errorf("the detail should say which version landed, got %q", resp.Items[0].Detail)
	}
}
