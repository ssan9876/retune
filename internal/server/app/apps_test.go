package app_test

import (
	"net/http"
	"strings"
	"testing"

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
