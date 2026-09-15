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
