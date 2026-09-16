package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

type compliancePolicyResp struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Rules       json.RawMessage `json:"rules"`
}

// TestCompliancePolicyCRUDAndRoles exercises the admin API's policy library
// end to end - spec §5's GET/POST/GET/POST/DELETE set - and its role gate: a
// read-only admin may read policies but not write them, the same split every
// other library (profiles, scripts, apps) already enforces.
func TestCompliancePolicyCRUDAndRoles(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	deviceID, _ := enrollDevice(t, a, srv, "PC-ROLE-CHECK")

	status, body := admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name":        "Baseline",
		"description": "The minimum every managed device must meet.",
		"rules":       json.RawMessage(`[{"type":"no_pending_reboot"}]`),
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	policy := decodeJSON[compliancePolicyResp](t, body)
	if policy.Name != "Baseline" || string(policy.Rules) != `[{"type":"no_pending_reboot"}]` {
		t.Fatalf("created policy = %+v", policy)
	}

	// A duplicate name is refused rather than silently accepted.
	if status, body = admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "Baseline", "rules": json.RawMessage(`[{"type":"no_pending_reboot"}]`),
	}); status != http.StatusConflict {
		t.Fatalf("duplicate name: %d %s", status, body)
	}

	// Rules that fail to parse are refused with the reason, before anything
	// is stored.
	if status, body = admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "Bad", "rules": json.RawMessage(`[{"type":"not_a_real_rule"}]`),
	}); status != http.StatusBadRequest {
		t.Fatalf("bad rule type: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/compliance-policies", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	list := decodeJSON[struct {
		Items []compliancePolicyResp `json:"items"`
		Total int                    `json:"total"`
	}](t, body)
	if list.Total != 1 {
		t.Fatalf("list total = %d, want 1", list.Total)
	}

	status, body = admin.do(http.MethodGet, "/compliance-policies/"+policy.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}

	status, body = admin.do(http.MethodPost, "/compliance-policies/"+policy.ID, map[string]any{
		"name": "Baseline", "description": "Updated.",
		"rules": json.RawMessage(`[{"type":"no_pending_reboot"},{"type":"tpm"}]`),
	})
	if status != http.StatusOK {
		t.Fatalf("update: %d %s", status, body)
	}
	updated := decodeJSON[compliancePolicyResp](t, body)
	if updated.Description != "Updated." {
		t.Fatalf("update did not stick: %+v", updated)
	}

	// The pass runs after the response, so the reply is 202 with the size of
	// the set it covers rather than a count of work already done.
	if status, body = admin.do(http.MethodPost, "/compliance-policies/"+policy.ID+"/evaluate", nil); status != http.StatusAccepted {
		t.Fatalf("evaluate: %d %s", status, body)
	}
	queued := decodeJSON[struct {
		DeviceCount int  `json:"device_count"`
		Started     bool `json:"started"`
	}](t, body)
	if !queued.Started {
		t.Fatalf("evaluate did not start a pass: %s", body)
	}

	if status, body = admin.do(http.MethodDelete, "/compliance-policies/"+policy.ID, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
	if status, _ = admin.do(http.MethodGet, "/compliance-policies/"+policy.ID, nil); status != http.StatusNotFound {
		t.Fatalf("get after delete: %d", status)
	}
	if status, _ = admin.do(http.MethodPost, "/compliance-policies/"+uuid.Must(uuid.NewV7()).String()+"/evaluate", nil); status != http.StatusNotFound {
		t.Fatalf("evaluate unknown policy: %d", status)
	}

	// Read-only: GET is open, every write is not - across every endpoint this
	// task adds, not just the policy library itself.
	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if status, body := ro.do(http.MethodGet, "/compliance-policies", nil); status != http.StatusOK {
		t.Fatalf("read-only list: %d %s", status, body)
	}
	if status, body := ro.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "Nope", "rules": json.RawMessage(`[{"type":"no_pending_reboot"}]`),
	}); status != http.StatusForbidden {
		t.Fatalf("read-only create: %d %s", status, body)
	}
	if status, body := ro.do(http.MethodGet, "/dashboard", nil); status != http.StatusOK {
		t.Fatalf("read-only dashboard: %d %s", status, body)
	}
	if status, body := ro.do(http.MethodGet, "/devices/"+deviceID.String()+"/compliance", nil); status != http.StatusOK {
		t.Fatalf("read-only device compliance: %d %s", status, body)
	}
}

// TestCompliancePolicyListDeviceCounts covers the policy list's per-policy
// rollup (console's "list with rollups", spec §6): one evaluated policy shows
// its compliant/non_compliant split, and a policy nothing has ever scored
// comes back at zero rather than missing the field entirely, so the console
// never has to special-case an unevaluated policy's row.
func TestCompliancePolicyListDeviceCounts(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	scored, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name: "Scored", Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("create scored policy: %v", err)
	}
	empty, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name: "Never evaluated", Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("create empty policy: %v", err)
	}

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": scored.ID.String(),
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}

	_, okMTLS := enrollDevice(t, a, srv, "PC-COMPLIANT")
	if status, body = send(t, okMTLS, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-COMPLIANT", PendingReboot: false,
	}); status != http.StatusOK {
		t.Fatalf("inventory upload (compliant): %d %s", status, body)
	}
	_, failMTLS := enrollDevice(t, a, srv, "PC-FAILS")
	if status, body = send(t, failMTLS, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-FAILS", PendingReboot: true,
	}); status != http.StatusOK {
		t.Fatalf("inventory upload (non-compliant): %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/compliance-policies", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	list := decodeJSON[struct {
		Items []struct {
			ID           string         `json:"id"`
			DeviceCounts map[string]int `json:"device_counts"`
		} `json:"items"`
	}](t, body)

	var gotScored, gotEmpty *map[string]int
	for i, item := range list.Items {
		switch item.ID {
		case scored.ID.String():
			gotScored = &list.Items[i].DeviceCounts
		case empty.ID.String():
			gotEmpty = &list.Items[i].DeviceCounts
		}
	}
	if gotScored == nil || (*gotScored)[store.ComplianceCompliant] != 1 || (*gotScored)[store.ComplianceNonCompliant] != 1 {
		t.Fatalf("scored device_counts = %+v", gotScored)
	}
	if gotEmpty == nil || (*gotEmpty)[store.ComplianceCompliant] != 0 || (*gotEmpty)[store.ComplianceNonCompliant] != 0 ||
		(*gotEmpty)[store.ComplianceUnknown] != 0 {
		t.Fatalf("empty policy device_counts = %+v, want all zero", gotEmpty)
	}
}

// TestDeviceComplianceEndpointAndDevicesListField covers both the per-device
// compliance endpoint and the "compliance" field the devices list gains
// (spec §5): a device with no assigned policy reads not_evaluated, and one
// that fails an assigned policy reads non_compliant in both places, with the
// failure's detail surfaced on the per-device endpoint.
func TestDeviceComplianceEndpointAndDevicesListField(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	deviceID, mtls := enrollDevice(t, a, srv, "PC-NONCOMPLIANT")

	// Before any policy is assigned, the device has nothing to be scored
	// against.
	status, body := admin.do(http.MethodGet, "/devices/"+deviceID.String()+"/compliance", nil)
	if status != http.StatusOK {
		t.Fatalf("device compliance: %d %s", status, body)
	}
	before := decodeJSON[struct {
		Overall  string `json:"overall"`
		Policies []any  `json:"policies"`
	}](t, body)
	if before.Overall != store.ComplianceNotEvaluated || len(before.Policies) != 0 {
		t.Fatalf("before assignment = %+v", before)
	}

	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "No pending reboot",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policy.ID.String(),
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}

	status, body = send(t, mtls, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname: "PC-NONCOMPLIANT", PendingReboot: true,
	})
	if status != http.StatusOK {
		t.Fatalf("inventory upload: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/devices/"+deviceID.String()+"/compliance", nil)
	if status != http.StatusOK {
		t.Fatalf("device compliance: %d %s", status, body)
	}
	after := decodeJSON[struct {
		Overall  string `json:"overall"`
		Policies []struct {
			PolicyID   string `json:"policy_id"`
			PolicyName string `json:"policy_name"`
			State      string `json:"state"`
			Failures   []struct {
				Rule   string `json:"rule"`
				Detail string `json:"detail"`
			} `json:"failures"`
		} `json:"policies"`
	}](t, body)
	if after.Overall != store.ComplianceNonCompliant {
		t.Fatalf("overall = %q, want non_compliant", after.Overall)
	}
	if len(after.Policies) != 1 || after.Policies[0].PolicyID != policy.ID.String() ||
		after.Policies[0].State != store.ComplianceNonCompliant || len(after.Policies[0].Failures) != 1 {
		t.Fatalf("policies = %+v", after.Policies)
	}
	// The name travels with the result, so the console does not have to fetch
	// the policy library to caption the row.
	if after.Policies[0].PolicyName != policy.Name {
		t.Fatalf("policy_name = %q, want %q", after.Policies[0].PolicyName, policy.Name)
	}

	// The devices list carries the same overall state for the same device.
	status, body = admin.do(http.MethodGet, "/devices", nil)
	if status != http.StatusOK {
		t.Fatalf("list devices: %d %s", status, body)
	}
	list := decodeJSON[struct {
		Items []struct {
			ID         string `json:"id"`
			Compliance string `json:"compliance"`
		} `json:"items"`
	}](t, body)
	found := false
	for _, d := range list.Items {
		if d.ID == deviceID.String() {
			found = true
			if d.Compliance != store.ComplianceNonCompliant {
				t.Fatalf("devices list compliance = %q, want non_compliant", d.Compliance)
			}
		}
	}
	if !found {
		t.Fatal("device missing from the list")
	}

	if status, _ := admin.do(http.MethodGet, "/devices/"+uuid.Must(uuid.NewV7()).String()+"/compliance", nil); status != http.StatusNotFound {
		t.Fatalf("unknown device: %d", status)
	}
}

// TestPolicyDevicesEndpointFiltersByState covers GET
// /compliance-policies/{id}/devices?state=, which is how the console's
// policy detail page drills from "3 non-compliant" to which three.
func TestPolicyDevicesEndpointFiltersByState(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "No pending reboot",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policy.ID.String(),
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}

	_, goodClient := enrollDevice(t, a, srv, "PC-GOOD")
	if status, body := send(t, goodClient, http.MethodPut, srv.URL+"/api/agent/v1/inventory",
		protocol.Inventory{Hostname: "PC-GOOD", PendingReboot: false}); status != http.StatusOK {
		t.Fatalf("good inventory: %d %s", status, body)
	}
	_, badClient := enrollDevice(t, a, srv, "PC-BAD")
	if status, body := send(t, badClient, http.MethodPut, srv.URL+"/api/agent/v1/inventory",
		protocol.Inventory{Hostname: "PC-BAD", PendingReboot: true}); status != http.StatusOK {
		t.Fatalf("bad inventory: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/compliance-policies/"+policy.ID.String()+"/devices", nil)
	if status != http.StatusOK {
		t.Fatalf("list policy devices: %d %s", status, body)
	}
	all := decodeJSON[struct {
		Total int `json:"total"`
	}](t, body)
	if all.Total != 2 {
		t.Fatalf("total = %d, want 2", all.Total)
	}

	status, body = admin.do(http.MethodGet, "/compliance-policies/"+policy.ID.String()+"/devices?state="+store.ComplianceNonCompliant, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered list: %d %s", status, body)
	}
	filtered := decodeJSON[struct {
		Total int `json:"total"`
		Items []struct {
			Hostname string `json:"hostname"`
		} `json:"items"`
	}](t, body)
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].Hostname != "PC-BAD" {
		t.Fatalf("filtered = %+v", filtered)
	}
}

// A compliance policy has nothing to configure per assignment, unlike a
// script or profile, so any options at all are refused - the same way an
// unknown item kind is refused, before anything is stored.
func TestComplianceAssignmentRejectsNonEmptyOptions(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance,
		"item_id":   uuid.Must(uuid.NewV7()).String(),
		"group_id":  store.BuiltinGroupID.String(),
		"mode":      "include",
		"options":   map[string]any{"unexpected": true},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", status, body)
	}

	// Empty options, however phrased, are accepted: {} is exactly as good as
	// omitting the field.
	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance,
		"item_id":   uuid.Must(uuid.NewV7()).String(),
		"group_id":  store.BuiltinGroupID.String(),
		"mode":      "include",
		"options":   map[string]any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("empty options should be accepted, got %d %s", status, body)
	}
}

// TestInventoryUploadTriggersComplianceEvaluation is the point of wiring
// Compliance into inventory.Service: a device does not have to wait for the
// 15-minute sweep to see where it stands against a policy assigned to it,
// because ingest evaluates it right after the upload that just changed the
// facts a rule reads.
func TestInventoryUploadTriggersComplianceEvaluation(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name:  "No pending reboot",
		Rules: json.RawMessage(`[{"type":"no_pending_reboot"}]`),
		Actor: "test",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance,
		"item_id":   policy.ID.String(),
		"group_id":  store.BuiltinGroupID.String(),
		"mode":      "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign policy: %d %s", status, body)
	}

	deviceID, mtls := enrollDevice(t, a, srv, "PC-COMPLIANT")
	status, body = send(t, mtls, http.MethodPut, srv.URL+"/api/agent/v1/inventory", protocol.Inventory{
		Hostname:      "PC-COMPLIANT",
		PendingReboot: false,
	})
	if status != http.StatusOK {
		t.Fatalf("inventory upload: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/"+compliance.ItemKindCompliance+"/"+policy.ID.String()+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("item status: %d %s", status, body)
	}
	resp := decodeJSON[struct {
		Items []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
		} `json:"items"`
	}](t, body)
	found := false
	for _, item := range resp.Items {
		if item.DeviceID == deviceID.String() {
			found = true
			if item.Status != store.ItemSucceeded {
				t.Fatalf("status = %q, want %q", item.Status, store.ItemSucceeded)
			}
		}
	}
	if !found {
		t.Fatalf("no result row for the uploading device, got %+v", resp.Items)
	}
}
