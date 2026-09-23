package app_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// TestHelpdeskRole: helpdesk reads, and takes the day-to-day device actions,
// but runs no code, destroys nothing and changes no policy.
func TestHelpdeskRole(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	help := signedIn(t, a, srv, store.RoleHelpdesk)
	ro := signedIn(t, a, srv, store.RoleReadOnly)
	id, _ := enrollDevice(t, a, srv, "PC-HELP")
	device := []string{id.String()}

	if status, _ := help.do(http.MethodGet, "/devices/"+id.String(), nil); status != http.StatusOK {
		t.Fatalf("helpdesk read: %d", status)
	}

	for _, typ := range []string{"lock", "restart", "refresh_inventory", "collect_logs", "rotate_local_admin_password"} {
		if status, body := help.do(http.MethodPost, "/commands", map[string]any{"device_ids": device, "type": typ}); status != http.StatusCreated {
			t.Errorf("helpdesk %s: %d %s", typ, status, body)
		}
		if status, _ := ro.do(http.MethodPost, "/commands", map[string]any{"device_ids": device, "type": typ}); status != http.StatusForbidden {
			t.Errorf("read-only %s: %d", typ, status)
		}
	}
	for name, req := range map[string]map[string]any{
		"run_powershell": {"device_ids": device, "type": "run_powershell", "script": "Get-Date"},
		"wipe":           {"device_ids": device, "type": "wipe", "confirm_hostname": "PC-HELP", "reason": "x"},
	} {
		if status, _ := help.do(http.MethodPost, "/commands", req); status != http.StatusForbidden {
			t.Errorf("helpdesk %s: %d, want 403", name, status)
		}
	}
	if status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": device, "type": "run_powershell", "script": "Get-Date",
	}); status != http.StatusCreated {
		t.Fatalf("admin run_powershell: %d %s", status, body)
	}

	// Nothing that defines what devices run.
	for path, body := range map[string]map[string]any{
		"/scripts":  {"name": "S", "body": "Get-Date"},
		"/profiles": {"name": "P", "settings": profileSettings()},
		"/apps":     {"name": "A", "package_id": "7zip.7zip"},
		"/assignments": {"item_kind": "script", "item_id": uuid.NewString(),
			"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include"},
	} {
		if status, _ := help.do(http.MethodPost, path, body); status != http.StatusForbidden {
			t.Errorf("helpdesk POST %s: %d, want 403", path, status)
		}
	}

	// Revealing a recovery key or password gets past the role check (404 for
	// one that doesn't exist); read-only is stopped at it.
	for _, path := range []string{"/bitlocker-keys/" + uuid.NewString() + "/reveal", "/admin-passwords/" + uuid.NewString() + "/reveal"} {
		if status, _ := help.do(http.MethodPost, path, map[string]any{"reason": "ticket 1"}); status != http.StatusNotFound {
			t.Errorf("helpdesk %s: %d, want 404", path, status)
		}
		if status, _ := ro.do(http.MethodPost, path, map[string]any{"reason": "ticket 1"}); status != http.StatusForbidden {
			t.Errorf("read-only %s: %d, want 403", path, status)
		}
	}

	// A helpdesk token can do what helpdesk can; helpdesk can't mint an admin
	// token.
	tok := makeToken(t, admin, "helpdesk-bot", store.RoleHelpdesk)
	if status, body := bearer(t, a, srv, tok.Token, http.MethodPost, "/commands",
		map[string]any{"device_ids": device, "type": "lock"}); status != http.StatusCreated {
		t.Fatalf("helpdesk token lock: %d %s", status, body)
	}
	if status, _ := bearer(t, a, srv, tok.Token, http.MethodPost, "/commands",
		map[string]any{"device_ids": device, "type": "run_powershell", "script": "Get-Date"}); status != http.StatusForbidden {
		t.Fatalf("helpdesk token run_powershell: %d", status)
	}
}
