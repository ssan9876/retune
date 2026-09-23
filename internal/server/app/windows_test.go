package app_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/server/store"
)

type windowResp struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Days     []string `json:"days"`
	Start    string   `json:"start"`
	Duration int      `json:"duration_minutes"`
}

// TestMaintenanceWindows: a window is defined once, assigned to a group, and
// reaches that group's devices, schedule and all, at check-in.
func TestMaintenanceWindows(t *testing.T) {
	// Approvals on, with a threshold every group exceeds: a window only holds
	// changes back, so assigning one never waits.
	a, srv := newTestAppWith(t, func(c *config.Server) {
		c.Approvals = config.ApprovalsConfig{Required: true, DeviceThreshold: 0}
	})
	admin := signedIn(t, a, srv, store.RoleAdmin)
	help := signedIn(t, a, srv, store.RoleHelpdesk)
	_, agent := enrollDevice(t, a, srv, "PC-WINDOW")

	for name, bad := range map[string]map[string]any{
		"no name":       {"start": "22:00", "duration_minutes": 60},
		"bad start":     {"name": "x", "start": "10pm", "duration_minutes": 60},
		"too long":      {"name": "x", "start": "22:00", "duration_minutes": 2000},
		"unknown day":   {"name": "x", "start": "22:00", "duration_minutes": 60, "days": []string{"funday"}},
		"zero duration": {"name": "x", "start": "22:00"},
	} {
		if status, body := admin.do(http.MethodPost, "/maintenance-windows", bad); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, status, body)
		}
	}
	weekend := map[string]any{"name": "Weekend nights", "days": []string{"Sat", "sun"}, "start": "22:00", "duration_minutes": 240}
	if status, _ := help.do(http.MethodPost, "/maintenance-windows", weekend); status != http.StatusForbidden {
		t.Fatalf("helpdesk created a window: %d", status)
	}
	status, body := admin.do(http.MethodPost, "/maintenance-windows", weekend)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	win := decodeJSON[windowResp](t, body)
	if win.Name != "Weekend nights" || len(win.Days) != 2 || win.Days[0] != "sat" || win.Start != "22:00" || win.Duration != 240 {
		t.Fatalf("window = %+v", win)
	}
	if status, _ := admin.do(http.MethodPost, "/maintenance-windows", weekend); status != http.StatusConflict {
		t.Fatalf("duplicate name: %d, want 409", status)
	}

	// Options are refused: the schedule is the window's own.
	assign := map[string]any{"item_kind": "window", "item_id": win.ID, "group_id": store.BuiltinGroupID.String(), "mode": "include"}
	withOptions := map[string]any{"options": map[string]any{"start": "01:00"}}
	for k, v := range assign {
		withOptions[k] = v
	}
	if status, _ := admin.do(http.MethodPost, "/assignments", withOptions); status != http.StatusBadRequest {
		t.Fatalf("a window assignment with options: %d, want 400", status)
	}
	if status, body := admin.do(http.MethodPost, "/assignments", assign); status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	checkin := func() []protocol.Item {
		t.Helper()
		status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "1.0.0"})
		if status != http.StatusOK {
			t.Fatalf("checkin: %d %s", status, body)
		}
		return decodeJSON[protocol.CheckinResponse](t, body).Items
	}
	items := checkin()
	if len(items) != 1 || items[0].Kind != protocol.ItemKindWindow || items[0].ID != win.ID {
		t.Fatalf("items = %+v", items)
	}
	var sched protocol.Window
	if err := json.Unmarshal(items[0].Options, &sched); err != nil || sched.Start != "22:00" || sched.DurationMinutes != 240 {
		t.Fatalf("schedule = %s, %v", items[0].Options, err)
	}

	// An edit reaches the device on its next check-in.
	weekend["start"] = "23:00"
	if status, body := admin.do(http.MethodPost, "/maintenance-windows/"+win.ID, weekend); status != http.StatusOK {
		t.Fatalf("update: %d %s", status, body)
	}
	if err := json.Unmarshal(checkin()[0].Options, &sched); err != nil || sched.Start != "23:00" {
		t.Fatalf("after the edit, schedule = %+v, %v", sched, err)
	}

	// Deleting it takes its assignments with it.
	if status, _ := admin.do(http.MethodDelete, "/maintenance-windows/"+win.ID, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d", status)
	}
	if items := checkin(); len(items) != 0 {
		t.Fatalf("after deletion, items = %+v", items)
	}
	if status, _ := admin.do(http.MethodGet, "/maintenance-windows/"+win.ID, nil); status != http.StatusNotFound {
		t.Fatalf("get deleted: %d", status)
	}
}
