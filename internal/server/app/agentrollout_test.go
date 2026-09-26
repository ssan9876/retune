package app_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/server/store"
)

type rolloutBody struct {
	Policy struct {
		Enabled      bool   `json:"enabled"`
		PilotGroupID string `json:"pilot_group_id"`
		DelayHours   int    `json:"delay_hours"`
	} `json:"policy"`
	Rollouts []struct {
		ID         string `json:"id"`
		Version    string `json:"version"`
		State      string `json:"state"`
		ApprovalID string `json:"approval_id"`
		Detail     string `json:"detail"`
	} `json:"rollouts"`
}

// An automatic rollout, end to end through the admin API: the policy, a pilot
// that passes, All devices held for a second administrator, and promotion
// once they approve - replayed by the admin API from the request the rollout
// wrote.
func TestAutomaticAgentRolloutThroughTheAPI(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestAppWith(t, func(c *config.Server) {
		c.Approvals = config.ApprovalsConfig{Required: true, DeviceThreshold: 50}
	})
	first := signedIn(t, a, srv, store.RoleAdmin)
	seedAdmin(t, a, "second@example.com", testPassword, store.RoleAdmin)
	second := newAdminClient(t, a, srv)
	if status, body := second.login("second@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}

	device, _ := enrollDevice(t, a, srv, "PC-PILOT")
	status, body := first.do(http.MethodPost, "/groups", map[string]any{"name": "Pilot", "kind": "static"})
	if status != http.StatusCreated {
		t.Fatalf("create group: %d %s", status, body)
	}
	pilot := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	if status, body := first.do(http.MethodPost, "/groups/"+pilot+"/members", map[string]any{"device_id": device.String()}); status >= 300 {
		t.Fatalf("add member: %d %s", status, body)
	}

	// Turning it on needs a pilot group, and not All devices.
	if status, _ := first.do(http.MethodPost, "/agent-rollout/policy", map[string]any{"enabled": true}); status != http.StatusBadRequest {
		t.Fatalf("enabled without a pilot group: %d, want 400", status)
	}
	if status, _ := first.do(http.MethodPost, "/agent-rollout/policy", map[string]any{
		"enabled": true, "pilot_group_id": store.BuiltinGroupID.String(),
	}); status != http.StatusBadRequest {
		t.Fatalf("All devices as the pilot: %d, want 400", status)
	}
	status, body = first.do(http.MethodPost, "/agent-rollout/policy", map[string]any{
		"enabled": true, "pilot_group_id": pilot, "delay_hours": 1,
	})
	if status != http.StatusOK {
		t.Fatalf("set policy: %d %s", status, body)
	}
	if p := decodeJSON[rolloutBody](t, body).Policy; !p.Enabled || p.PilotGroupID != pilot || p.DelayHours != 1 {
		t.Fatalf("policy = %+v", p)
	}

	if status, body := uploadAgentVersion(t, first, "1.2.0", "agent bytes"); status != http.StatusCreated {
		t.Fatalf("upload: %d %s", status, body)
	}
	v, err := a.Store.Q().GetAgentVersionByVersion(ctx, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AgentRollout.Start(ctx, v); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.Q().SetItemStatus(ctx, store.ItemStatus{
		DeviceID: device, ItemKind: protocol.ItemKindAgent, ItemID: v.ID,
		Status: store.ItemSucceeded, Detail: "running this version", Version: 1, UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Hour)
	a.AgentRollout.Now = func() time.Time { return later }
	if _, err := a.AgentRollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	status, body = first.do(http.MethodGet, "/agent-rollout", nil)
	if status != http.StatusOK {
		t.Fatalf("get rollout: %d %s", status, body)
	}
	ro := decodeJSON[rolloutBody](t, body).Rollouts[0]
	if ro.State != store.RolloutPromoting || ro.ApprovalID == "" {
		t.Fatalf("All devices should wait for approval: %+v", ro)
	}

	// The second administrator approves the request the rollout made.
	status, body = second.do(http.MethodPost, "/approvals/"+ro.ApprovalID+"/approve", map[string]any{"reason": "pilot looks fine"})
	if status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, body)
	}
	if res := decodeJSON[approvalBody](t, body).Approval.Result; res.Assignment == nil || res.Error != "" {
		t.Fatalf("the approval should have made the assignment: %+v", res)
	}
	if _, err := a.AgentRollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	_, body = first.do(http.MethodGet, "/agent-rollout", nil)
	if ro := decodeJSON[rolloutBody](t, body).Rollouts[0]; ro.State != store.RolloutPromoted {
		t.Fatalf("approved, the build reaches everyone: %+v", ro)
	}
	if _, err := a.Store.Q().GetAssignmentFor(ctx, protocol.ItemKindAgent, v.ID, store.BuiltinGroupID, store.ModeInclude); err != nil {
		t.Fatalf("All devices assignment: %v", err)
	}

	// Resuming a rollout that isn't halted is refused.
	if status, _ := first.do(http.MethodPost, "/agent-rollouts/"+ro.ID+"/resume", nil); status != http.StatusConflict {
		t.Fatalf("resume a promoted rollout: %d, want 409", status)
	}
}

// The release feed is off in tests: the API says so instead of pretending.
func TestReleasesEndpointsWithTheFeedOff(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.do(http.MethodGet, "/releases", nil)
	if status != http.StatusOK {
		t.Fatalf("list releases: %d %s", status, body)
	}
	got := decodeJSON[struct {
		Feed struct {
			Enabled bool `json:"enabled"`
		} `json:"feed"`
		Items []any `json:"items"`
	}](t, body)
	if got.Feed.Enabled || len(got.Items) != 0 {
		t.Fatalf("releases = %+v", got)
	}
	if status, _ := admin.do(http.MethodPost, "/releases/check", nil); status != http.StatusConflict {
		t.Fatalf("check with the feed off: %d, want 409", status)
	}
	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := viewer.do(http.MethodPost, "/agent-rollout/policy", map[string]any{"enabled": false}); status != http.StatusForbidden {
		t.Fatalf("read-only changing the policy: %d, want 403", status)
	}
}

// A halted rollout is something an alert rule can be about.
func TestAgentRolloutHaltedAlertRule(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.do(http.MethodPost, "/notification-channels", map[string]any{
		"name": "Ops", "kind": "webhook", "config": map[string]any{"url": "https://hooks.example.com/retune"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create channel: %d %s", status, body)
	}
	ch := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	status, body = admin.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Rollout halted", "kind": "agent_rollout_halted", "channel_id": ch,
	})
	if status != http.StatusCreated {
		t.Fatalf("create rule: %d %s", status, body)
	}
	if status, _ := admin.do(http.MethodPost, "/alert-rules", map[string]any{
		"name": "Wrong", "kind": "agent_rollout_halted", "channel_id": ch, "params": map[string]any{"hours": 3},
	}); status != http.StatusBadRequest {
		t.Fatalf("a parameter the kind doesn't take: %d, want 400", status)
	}
}
