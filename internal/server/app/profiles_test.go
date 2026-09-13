package app_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type profileResp struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	CurrentVersion int                `json:"current_version"`
	Settings       []protocol.Setting `json:"settings"`
}

func profileSettings() []map[string]any {
	return []map[string]any{
		{"kind": "service", "name": "Spooler", "state": "stopped"},
		{"kind": "file", "path": "C:/temp/motd.txt", "content_base64": "aGk="},
	}
}

func assignProfile(t *testing.T, admin *adminClient, profileID string, revert bool) {
	t.Helper()
	status, out := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": protocol.ItemKindProfile, "item_id": profileID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"revert_on_removal": revert},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, out)
	}
}

func TestProfileReachesTheAgentAndReportsBack(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-MANAGED")

	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Baseline", "settings": profileSettings(),
	})
	if status != http.StatusCreated {
		t.Fatalf("create profile: %d %s", status, body)
	}
	profile := decodeJSON[profileResp](t, body)

	assignProfile(t, admin, profile.ID, true)

	// Check-in names the profile, its version and the options.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindProfile || items[0].Version != 1 {
		t.Fatalf("items = %+v", items)
	}
	if !strings.Contains(string(items[0].Options), "revert_on_removal") {
		t.Errorf("the options should travel with the item, got %s", items[0].Options)
	}

	// The settings are fetched separately, once per version.
	url := fmt.Sprintf("%s/api/agent/v1/profiles/%s/versions/1", srv.URL, profile.ID)
	status, body = send(t, agent, http.MethodGet, url, nil)
	if status != http.StatusOK {
		t.Fatalf("fetch version: %d %s", status, body)
	}
	version := decodeJSON[protocol.ProfileVersionResponse](t, body)
	if len(version.Settings) != 2 || version.Settings[0].Name != "Spooler" {
		t.Fatalf("settings = %+v", version.Settings)
	}

	// Reporting per-setting results rolls up into the profile's status.
	status, body = send(t, agent, http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/profiles/%s/status", srv.URL, profile.ID),
		protocol.ProfileStatus{Version: 1, Settings: []protocol.SettingResult{
			{Identity: "service:spooler", Status: protocol.SettingRemediated},
			{Identity: "file:c:/temp/motd.txt", Status: protocol.SettingError, Detail: "access denied"},
		}})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/profiles/"+profile.ID+"/settings", nil)
	if status != http.StatusOK {
		t.Fatalf("settings status: %d %s", status, body)
	}
	resp := decodeJSON[struct {
		Rollup map[string]int `json:"rollup"`
		Items  []struct {
			Identity string `json:"identity"`
			Status   string `json:"status"`
			Detail   string `json:"detail"`
			Hostname string `json:"hostname"`
		} `json:"items"`
	}](t, body)
	if resp.Rollup[store.SettingRemediated] != 1 || resp.Rollup[store.SettingError] != 1 {
		t.Fatalf("rollup = %v", resp.Rollup)
	}
	var failing bool
	for _, row := range resp.Items {
		if row.Status == store.SettingError {
			failing = true
			if row.Detail != "access denied" || row.Hostname != "DESKTOP-MANAGED" {
				t.Errorf("the failing setting should say where and why, got %+v", row)
			}
		}
	}
	if !failing {
		t.Fatal("the failing setting should be listed")
	}

	// The profile's own status says it failed, naming the setting.
	status, body = admin.do(http.MethodGet, "/items/profile/"+profile.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("item status: %d %s", status, body)
	}
	item := decodeJSON[struct {
		Rollup map[string]int `json:"rollup"`
		Items  []struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"items"`
	}](t, body)
	if item.Rollup[store.ItemFailed] != 1 {
		t.Fatalf("item rollup = %v", item.Rollup)
	}
	if !strings.Contains(item.Items[0].Detail, "file:c:/temp/motd.txt") {
		t.Errorf("the profile status should name the failing setting, got %q", item.Items[0].Detail)
	}
}

func TestUnassignedProfileIsNotReadable(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-CURIOUS")

	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Private", "settings": profileSettings(),
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	profile := decodeJSON[profileResp](t, body)

	url := fmt.Sprintf("%s/api/agent/v1/profiles/%s/versions/1", srv.URL, profile.ID)
	if status, _ := send(t, agent, http.MethodGet, url, nil); status != http.StatusNotFound {
		t.Fatalf("an unassigned profile must not be readable, got %d", status)
	}

	assignProfile(t, admin, profile.ID, false)
	if status, body := send(t, agent, http.MethodGet, url, nil); status != http.StatusOK {
		t.Fatalf("an assigned profile should be readable: %d %s", status, body)
	}
}

func TestBadSettingsAreRefusedWithTheReason(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	// HKCU needs the signed-in user's hive, which is not supported yet, so it
	// is refused when the profile is saved rather than erroring on every
	// device forever.
	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "User hive", "settings": []map[string]any{
			{"kind": "registry", "hive": "HKCU", "key": "Software/X", "name": "Y", "type": "REG_SZ", "data": "z"},
		},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", status, body)
	}
	if !strings.Contains(string(body), "HKCU") {
		t.Errorf("the error should explain what is wrong, got %s", body)
	}

	// And a setting the author repeated within one profile.
	status, body = admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Repeated", "settings": []map[string]any{
			{"kind": "service", "name": "Spooler", "state": "stopped"},
			{"kind": "service", "name": "spooler", "state": "running"},
		},
	})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "both configure") {
		t.Fatalf("want a duplicate-setting error, got %d %s", status, body)
	}
}

func TestEditingSettingsMakesANewVersion(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Evolving", "settings": profileSettings(),
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	profile := decodeJSON[profileResp](t, body)

	// Renaming alone does not.
	status, body = admin.do(http.MethodPost, "/profiles/"+profile.ID, map[string]any{
		"name": "Renamed", "settings": profileSettings(),
	})
	if status != http.StatusOK {
		t.Fatalf("rename: %d %s", status, body)
	}
	if v := decodeJSON[profileResp](t, body).CurrentVersion; v != 1 {
		t.Fatalf("renaming should not make a version, got %d", v)
	}

	changed := append(profileSettings(), map[string]any{
		"kind": "registry", "hive": "HKLM", "key": "SOFTWARE/Retune",
		"name": "Managed", "type": "REG_DWORD", "data": "1",
	})
	status, body = admin.do(http.MethodPost, "/profiles/"+profile.ID, map[string]any{
		"name": "Renamed", "settings": changed,
	})
	if status != http.StatusOK {
		t.Fatalf("edit: %d %s", status, body)
	}
	if v := decodeJSON[profileResp](t, body).CurrentVersion; v != 2 {
		t.Fatalf("changed settings should make version 2, got %d", v)
	}
}

func TestProfilesAreClosedToReadOnlyAdmins(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/profiles", nil); status != http.StatusOK {
		t.Error("a read-only admin should be able to list profiles")
	}
	if status, _ := c.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Nope", "settings": profileSettings(),
	}); status != http.StatusForbidden {
		t.Errorf("a read-only admin should not create profiles, got %d", status)
	}
}
