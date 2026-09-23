package app_test

import (
	"net/http"
	"testing"

	"retune/internal/server/store"
)

// TestPhasedRolloutAPI: a rollout is checked, stored, and shown with how far
// it has got.
func TestPhasedRolloutAPI(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.do(http.MethodPost, "/scripts", map[string]any{"name": "Patch", "body": "Get-Date"})
	if status != http.StatusCreated {
		t.Fatalf("create script: %d %s", status, body)
	}
	scriptID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	all := store.BuiltinGroupID.String()
	req := func(mode string, rollout map[string]any) map[string]any {
		return map[string]any{"item_kind": "script", "item_id": scriptID, "group_id": all, "mode": mode, "rollout": rollout}
	}

	for name, bad := range map[string]map[string]any{
		"zero percent":       req("include", map[string]any{"percent": 0}),
		"over 100":           req("include", map[string]any{"percent": 101}),
		"step without hours": req("include", map[string]any{"percent": 10, "step_percent": 10}),
		"hours without step": req("include", map[string]any{"percent": 10, "step_hours": 24}),
		"a phased exclusion": req("exclude", map[string]any{"percent": 10}),
		"too long a step":    req("include", map[string]any{"percent": 10, "step_percent": 10, "step_hours": 721}),
	} {
		if status, body := admin.do(http.MethodPost, "/assignments", bad); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, status, body)
		}
	}

	status, body = admin.do(http.MethodPost, "/assignments", req("include", map[string]any{"percent": 10, "step_percent": 30, "step_hours": 24}))
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}
	type rollout struct {
		Percent        int     `json:"percent"`
		StepPercent    int     `json:"step_percent"`
		StepHours      int     `json:"step_hours"`
		CurrentPercent int     `json:"current_percent"`
		FullAt         *string `json:"full_at"`
	}
	type assignment struct {
		Rollout *rollout `json:"rollout"`
	}
	got := decodeJSON[assignment](t, body).Rollout
	if got == nil || got.Percent != 10 || got.CurrentPercent != 10 || got.StepPercent != 30 || got.FullAt == nil {
		t.Fatalf("rollout = %+v", got)
	}
	_, body = admin.do(http.MethodGet, "/assignments?item_kind=script&item_id="+scriptID, nil)
	items := decodeJSON[struct {
		Items []assignment `json:"items"`
	}](t, body).Items
	if len(items) != 1 || items[0].Rollout == nil || items[0].Rollout.CurrentPercent != 10 {
		t.Fatalf("listed = %+v", items)
	}

	// Replacing it at 100% ends the phasing.
	if status, body := admin.do(http.MethodPost, "/assignments", req("include", map[string]any{"percent": 100})); status != http.StatusCreated {
		t.Fatalf("replace: %d %s", status, body)
	} else if decodeJSON[assignment](t, body).Rollout != nil {
		t.Fatalf("a full include shows no rollout: %s", body)
	}
}
