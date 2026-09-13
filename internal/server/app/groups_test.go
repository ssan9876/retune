package app_test

import (
	"net/http"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

type groupResp struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Rule        string `json:"rule"`
	MemberCount int    `json:"member_count"`
}

func TestGroupAPI(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleAdmin)

	t.Run("the built-in group is there from the start", func(t *testing.T) {
		status, body := c.do(http.MethodGet, "/groups", nil)
		if status != http.StatusOK {
			t.Fatalf("list groups: %d %s", status, body)
		}
		list := decodeJSON[struct {
			Items []groupResp `json:"items"`
		}](t, body)
		if len(list.Items) != 1 || list.Items[0].Kind != store.GroupBuiltin {
			t.Fatalf("want just the built-in group, got %+v", list.Items)
		}
	})

	var dynamicID string
	t.Run("create a dynamic group", func(t *testing.T) {
		status, body := c.do(http.MethodPost, "/groups", map[string]string{
			"name": "Plenty of RAM", "kind": "dynamic", "rule": "ram_gb >= 16",
		})
		if status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, body)
		}
		g := decodeJSON[groupResp](t, body)
		if g.Rule != "ram_gb >= 16" {
			t.Fatalf("rule = %q", g.Rule)
		}
		dynamicID = g.ID
	})

	t.Run("a rule that does not parse says where", func(t *testing.T) {
		status, body := c.do(http.MethodPost, "/groups", map[string]string{
			"name": "Broken", "kind": "dynamic", "rule": "ram_gb >= ",
		})
		if status != http.StatusBadRequest {
			t.Fatalf("want 400, got %d %s", status, body)
		}
		resp := decodeJSON[struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Offset  int    `json:"offset"`
		}](t, body)
		if resp.Code != "invalid_rule" {
			t.Fatalf("code = %q", resp.Code)
		}
		if resp.Offset == 0 && resp.Message == "" {
			t.Fatal("the error should say where and why")
		}
	})

	t.Run("preview reports a count without saving", func(t *testing.T) {
		status, body := c.do(http.MethodPost, "/groups/preview", map[string]string{
			"rule": "hostname LIKE '%'",
		})
		if status != http.StatusOK {
			t.Fatalf("preview: %d %s", status, body)
		}
		resp := decodeJSON[struct {
			Total int `json:"total"`
		}](t, body)
		if resp.Total != 0 {
			t.Fatalf("no devices are enrolled, so the count should be 0, got %d", resp.Total)
		}

		status, _ = c.do(http.MethodGet, "/groups", nil)
		if status != http.StatusOK {
			t.Fatal("previewing must not have changed anything")
		}
	})

	t.Run("a dynamic group's members cannot be set by hand", func(t *testing.T) {
		status, body := c.do(http.MethodPost, "/groups/"+dynamicID+"/members",
			map[string]string{"device_id": "00000000-0000-0000-0000-0000000000ff"})
		if status != http.StatusConflict {
			t.Fatalf("want 409, got %d %s", status, body)
		}
	})

	t.Run("the built-in group cannot be deleted", func(t *testing.T) {
		status, body := c.do(http.MethodDelete, "/groups/"+store.BuiltinGroupID.String(), nil)
		if status != http.StatusConflict {
			t.Fatalf("want 409, got %d %s", status, body)
		}
	})

	t.Run("names are unique", func(t *testing.T) {
		status, body := c.do(http.MethodPost, "/groups", map[string]string{
			"name": "plenty of ram", "kind": "static",
		})
		if status != http.StatusConflict {
			t.Fatalf("want 409, got %d %s", status, body)
		}
	})

	t.Run("assign an item and read the rollup", func(t *testing.T) {
		item := "018f0000-0000-7000-8000-00000000abcd"
		status, body := c.do(http.MethodPost, "/assignments", map[string]string{
			"item_kind": "script", "item_id": item,
			"group_id": store.BuiltinGroupID.String(), "mode": "include",
		})
		if status != http.StatusCreated {
			t.Fatalf("create assignment: %d %s", status, body)
		}
		assignment := decodeJSON[struct {
			ID string `json:"id"`
		}](t, body)

		status, body = c.do(http.MethodGet, "/assignments?item_kind=script&item_id="+item, nil)
		if status != http.StatusOK {
			t.Fatalf("list assignments: %d %s", status, body)
		}

		status, body = c.do(http.MethodGet, "/items/script/"+item+"/status", nil)
		if status != http.StatusOK {
			t.Fatalf("item status: %d %s", status, body)
		}

		status, body = c.do(http.MethodDelete, "/assignments/"+assignment.ID, nil)
		if status != http.StatusNoContent {
			t.Fatalf("delete assignment: %d %s", status, body)
		}
	})

	t.Run("delete the group", func(t *testing.T) {
		status, body := c.do(http.MethodDelete, "/groups/"+dynamicID, nil)
		if status != http.StatusNoContent {
			t.Fatalf("delete: %d %s", status, body)
		}
	})
}

func TestGroupAPIIsClosedToReadOnlyAdmins(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/groups", nil); status != http.StatusOK {
		t.Error("a read-only admin should be able to list groups")
	}
	if status, _ := c.do(http.MethodPost, "/groups", map[string]string{
		"name": "Nope", "kind": "static",
	}); status != http.StatusForbidden {
		t.Errorf("a read-only admin should not create groups, got %d", status)
	}
	if status, _ := c.do(http.MethodPost, "/groups/preview", map[string]string{
		"rule": "ram_gb > 0",
	}); status != http.StatusForbidden {
		t.Errorf("a read-only admin should not run rules, got %d", status)
	}
}

// TestEffectiveItemsReachCheckin is the point of the whole milestone: an item
// assigned to a group the device belongs to comes back on its next check-in,
// and an exclude anywhere takes it away again.
func TestEffectiveItemsReachCheckin(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	deviceID, agent := enrollDevice(t, a, srv, "DESKTOP-GROUPED")

	checkinItems := func() []protocol.Item {
		t.Helper()
		status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
			protocol.CheckinRequest{AgentVersion: "1.0.0"})
		if status != http.StatusOK {
			t.Fatalf("checkin: %d %s", status, body)
		}
		return decodeJSON[protocol.CheckinResponse](t, body).Items
	}

	// Enrolling puts the device in the built-in group, so nothing else is
	// needed for a fleet-wide assignment to reach it.
	if items := checkinItems(); len(items) != 0 {
		t.Fatalf("nothing is assigned yet, got %v", items)
	}

	item := "01a09983-0000-7000-8000-0000000000aa"
	status, body := admin.do(http.MethodPost, "/assignments", map[string]string{
		"item_kind": "script", "item_id": item,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	items := checkinItems()
	if len(items) != 1 || items[0].ID != item || items[0].Kind != "script" {
		t.Fatalf("the assigned item should reach the device, got %v", items)
	}

	// A group that excludes the same item takes it away, even though the
	// include is still there.
	status, body = admin.do(http.MethodPost, "/groups", map[string]string{
		"name": "Held back", "kind": "static",
	})
	if status != http.StatusCreated {
		t.Fatalf("create group: %d %s", status, body)
	}
	held := decodeJSON[groupResp](t, body)

	if status, body := admin.do(http.MethodPost, "/groups/"+held.ID+"/members",
		map[string]string{"device_id": deviceID.String()}); status != http.StatusNoContent {
		t.Fatalf("add member: %d %s", status, body)
	}
	if status, body := admin.do(http.MethodPost, "/assignments", map[string]string{
		"item_kind": "script", "item_id": item,
		"group_id": held.ID, "mode": "exclude",
	}); status != http.StatusCreated {
		t.Fatalf("exclude: %d %s", status, body)
	}

	if items := checkinItems(); len(items) != 0 {
		t.Fatalf("exclude must win on check-in too, got %v", items)
	}
}
