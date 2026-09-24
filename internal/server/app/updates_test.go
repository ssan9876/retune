package app_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

// TestWindowsUpdateReporting: what a device reports missing reaches its
// compliance, and helpdesk can have updates installed.
func TestWindowsUpdateReporting(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	help := signedIn(t, a, srv, store.RoleHelpdesk)

	status, body := admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "Patched", "rules": json.RawMessage(`[{"type":"max_missing_security_updates","count":0}]`),
	})
	if status != http.StatusCreated {
		t.Fatalf("create policy: %d %s", status, body)
	}
	policyID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	if status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policyID, "group_id": store.BuiltinGroupID.String(), "mode": "include",
	}); status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	deviceID, mtls := enrollDevice(t, a, srv, "PC-UNPATCHED")
	if status, body := send(t, mtls, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-UNPATCHED",
		WindowsUpdates: &protocol.UpdateStatus{ScannedAt: time.Now().UTC(), Pending: []protocol.PendingUpdate{
			{Title: "2026-09 Cumulative Update (KB5065426)", KB: "KB5065426", Severity: "Critical", Security: true, RebootRequired: true},
			{Title: "A driver"},
		}},
	}); status != http.StatusOK {
		t.Fatalf("inventory: %d %s", status, body)
	}
	_, body = admin.do(http.MethodGet, "/devices/"+deviceID.String()+"/compliance", nil)
	if !strings.Contains(string(body), `"overall":"non_compliant"`) || !strings.Contains(string(body), "KB5065426") {
		t.Fatalf("compliance = %s", body)
	}
	_, body = admin.do(http.MethodGet, "/devices/"+deviceID.String(), nil)
	if !strings.Contains(string(body), `"windows_updates"`) {
		t.Fatalf("the device's inventory doesn't carry its updates: %s", body)
	}

	queue := map[string]any{"device_ids": []string{deviceID.String()}, "type": "install_updates", "scope": "security", "restart_policy": "if_required"}
	if status, body := help.do(http.MethodPost, "/commands", queue); status != http.StatusCreated {
		t.Fatalf("helpdesk installs updates: %d %s", status, body)
	}
	for name, bad := range map[string]map[string]any{
		"scope":   {"device_ids": []string{deviceID.String()}, "type": "install_updates", "scope": "drivers"},
		"restart": {"device_ids": []string{deviceID.String()}, "type": "install_updates", "restart_policy": "whenever"},
	} {
		if status, _ := admin.do(http.MethodPost, "/commands", bad); status != http.StatusBadRequest {
			t.Errorf("a bad %s: %d", name, status)
		}
	}
}
