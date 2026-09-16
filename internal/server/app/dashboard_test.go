package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

type dashboardResp struct {
	Devices struct {
		Active  int `json:"active"`
		Stale   int `json:"stale"`
		Retired int `json:"retired"`
		Total   int `json:"total"`
	} `json:"devices"`
	Compliance struct {
		Compliant    int `json:"compliant"`
		NonCompliant int `json:"non_compliant"`
		Unknown      int `json:"unknown"`
		NotEvaluated int `json:"not_evaluated"`
	} `json:"compliance"`
	FailedDeployments struct {
		Script  int `json:"script"`
		App     int `json:"app"`
		Profile int `json:"profile"`
		Agent   int `json:"agent"`
	} `json:"failed_deployments"`
	AgentVersions []struct {
		Version string `json:"version"`
		Count   int    `json:"count"`
	} `json:"agent_versions"`
	OSBuilds []struct {
		Build string `json:"build"`
		Count int    `json:"count"`
	} `json:"os_builds"`
}

// TestDashboardNumbers seeds a small fleet exercising every FleetBar bucket -
// one active device that has checked in, one active device that never has
// (stale by devices.go's own definition, nil last_seen_at), and one retired
// device - plus a non-compliant policy and a failed profile setting, and
// checks the dashboard's numbers against that fleet (spec §5). The device
// buckets must be mutually exclusive: their sum must equal the total, and no
// device may satisfy more than one of "retired", "stale" or "active".
func TestDashboardNumbers(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	// An active, freshly checked-in device: contributes to devices.active and
	// to the agent_versions/os_builds top lists.
	_, activeClient := enrollDevice(t, a, srv, "PC-ACTIVE")
	if status, body := send(t, activeClient, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.2.3"}); status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	if status, body := send(t, activeClient, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-ACTIVE", OS: protocol.OSInfo{Build: "26200"},
	}); status != http.StatusOK {
		t.Fatalf("inventory: %d %s", status, body)
	}

	// An active device that has never checked in: nil last_seen_at makes it
	// stale by devices.go's own definition (devices.go:15-42), matching the
	// dashboard's devices.stale.
	_, staleClient := enrollDevice(t, a, srv, "PC-STALE")

	// A policy assigned to everyone, so PC-STALE (never inventoried) reads
	// unknown and PC-ACTIVE (inventoried, pending reboot) reads non_compliant.
	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "No pending reboot",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policy.ID.String(),
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	}); status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}
	if status, body := send(t, activeClient, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-ACTIVE", OS: protocol.OSInfo{Build: "26200"}, PendingReboot: true,
	}); status != http.StatusOK {
		t.Fatalf("re-upload inventory: %d %s", status, body)
	}
	_ = staleClient // PC-STALE deliberately never uploads inventory or checks in.

	// PC-STALE is never inventoried, so nothing has evaluated it yet (only
	// inventory upload and the sweep trigger evaluation, not enrollment).
	// Run the same sweep the periodic job runs so it gets a result: with no
	// inventory on file, the rule engine reports unknown rather than
	// non_compliant or compliant (buildFacts' comment on the missing-inventory
	// case), which is what should land in the dashboard's compliance.unknown.
	if _, err := a.Compliance.EvaluateActive(ctx, a.Store.Q(), time.Now()); err != nil {
		t.Fatalf("evaluate active: %v", err)
	}

	// A retired device: falls out of both the compliance and failed-deployment
	// buckets, and out of devices.active/stale into devices.retired.
	retiredID, _ := enrollDevice(t, a, srv, "PC-RETIRED")
	if status, body := admin.do(http.MethodPost, "/devices/"+retiredID.String()+"/retire", nil); status != http.StatusNoContent {
		t.Fatalf("retire: %d %s", status, body)
	}

	// A failed profile setting on the active device, for failed_deployments.profile.
	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Baseline", "settings": []map[string]any{
			{"kind": "service", "name": "Spooler", "state": "stopped"},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create profile: %d %s", status, body)
	}
	profile := decodeJSON[profileResp](t, body)
	assignProfile(t, admin, profile.ID, false)
	status, body = send(t, activeClient, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.2.3"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	status, body = send(t, activeClient, http.MethodPost,
		srv.URL+"/api/agent/v1/profiles/"+profile.ID+"/status",
		protocol.ProfileStatus{Version: 1, Settings: []protocol.SettingResult{
			{Identity: "service:spooler", Status: protocol.SettingError, Detail: "access denied"},
		}})
	if status != http.StatusNoContent {
		t.Fatalf("report profile status: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/dashboard", nil)
	if status != http.StatusOK {
		t.Fatalf("dashboard: %d %s", status, body)
	}
	dash := decodeJSON[dashboardResp](t, body)

	if dash.Devices.Total != 3 {
		t.Fatalf("devices.total = %d, want 3", dash.Devices.Total)
	}
	if dash.Devices.Active != 1 || dash.Devices.Stale != 1 || dash.Devices.Retired != 1 {
		t.Fatalf("devices = %+v", dash.Devices)
	}
	if sum := dash.Devices.Active + dash.Devices.Stale + dash.Devices.Retired; sum != dash.Devices.Total {
		t.Fatalf("buckets are not mutually exclusive: active+stale+retired = %d, total = %d", sum, dash.Devices.Total)
	}

	// Compliance counts only active devices (PC-RETIRED excluded): PC-ACTIVE
	// is non_compliant (pending reboot), PC-STALE is unknown (no inventory).
	if dash.Compliance.NonCompliant != 1 || dash.Compliance.Unknown != 1 || dash.Compliance.Compliant != 0 {
		t.Fatalf("compliance = %+v", dash.Compliance)
	}

	if dash.FailedDeployments.Profile != 1 {
		t.Fatalf("failed_deployments.profile = %d, want 1", dash.FailedDeployments.Profile)
	}
	if dash.FailedDeployments.Script != 0 || dash.FailedDeployments.App != 0 || dash.FailedDeployments.Agent != 0 {
		t.Fatalf("failed_deployments should only count real failures of those kinds: %+v", dash.FailedDeployments)
	}

	foundVersion := false
	for _, v := range dash.AgentVersions {
		if v.Version == "1.2.3" {
			foundVersion = true
			if v.Count != 1 {
				t.Fatalf("agent version count = %d, want 1", v.Count)
			}
		}
	}
	if !foundVersion {
		t.Fatalf("agent_versions missing 1.2.3: %+v", dash.AgentVersions)
	}
	foundBuild := false
	for _, b := range dash.OSBuilds {
		if b.Build == "26200" {
			foundBuild = true
		}
	}
	if !foundBuild {
		t.Fatalf("os_builds missing 26200: %+v", dash.OSBuilds)
	}
}
