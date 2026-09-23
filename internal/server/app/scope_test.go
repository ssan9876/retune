package app_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// scopedFixture is a fleet of two groups with one device each, an unscoped
// admin, and an admin limited to the first group.
type scopedFixture struct {
	fleet, site         *adminClient
	siteID              string
	inGroup, outGroup   string
	inDevice, outDevice uuid.UUID
}

func newScopedFixture(t *testing.T) *scopedFixture {
	t.Helper()
	a, srv := newTestApp(t)
	fleet := signedIn(t, a, srv, store.RoleAdmin)
	inDevice, _ := enrollDevice(t, a, srv, "SITE-A-PC")
	outDevice, _ := enrollDevice(t, a, srv, "SITE-B-PC")

	group := func(name string, member uuid.UUID) string {
		status, body := fleet.do(http.MethodPost, "/groups", map[string]any{"name": name, "kind": "static"})
		if status != http.StatusCreated {
			t.Fatalf("create group: %d %s", status, body)
		}
		id := decodeJSON[map[string]any](t, body)["id"].(string)
		if status, body := fleet.do(http.MethodPost, "/groups/"+id+"/members", map[string]any{"device_id": member.String()}); status != http.StatusNoContent && status != http.StatusCreated {
			t.Fatalf("add member: %d %s", status, body)
		}
		return id
	}
	inGroup := group("Site A", inDevice)
	outGroup := group("Site B", outDevice)

	seeded := seedAdmin(t, a, "site-a@example.com", testPassword, store.RoleAdmin)
	if status, body := fleet.do(http.MethodPut, "/admins/"+seeded.ID.String()+"/scope",
		map[string]any{"group_ids": []string{inGroup}}); status != http.StatusNoContent {
		t.Fatalf("set scope: %d %s", status, body)
	}
	site := newAdminClient(t, a, srv)
	if status, body := site.login("site-a@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	return &scopedFixture{fleet: fleet, site: site, siteID: seeded.ID.String(),
		inGroup: inGroup, outGroup: outGroup, inDevice: inDevice, outDevice: outDevice}
}

func TestAScopedAdminSeesOnlyTheirDevices(t *testing.T) {
	f := newScopedFixture(t)

	_, body := f.site.do(http.MethodGet, "/devices", nil)
	if !strings.Contains(string(body), "SITE-A-PC") || strings.Contains(string(body), "SITE-B-PC") {
		t.Errorf("device list: %s", body)
	}
	if status, _ := f.site.do(http.MethodGet, "/devices/"+f.inDevice.String(), nil); status != http.StatusOK {
		t.Errorf("own device: %d", status)
	}
	// Outside the scope a device is not forbidden but absent, so its id
	// cannot be probed for.
	for _, path := range []string{"", "/software", "/bitlocker-keys", "/compliance"} {
		if status, _ := f.site.do(http.MethodGet, "/devices/"+f.outDevice.String()+path, nil); status != http.StatusNotFound {
			t.Errorf("other device%s: %d, want 404", path, status)
		}
	}
	if status, _ := f.site.do(http.MethodPost, "/devices/"+f.outDevice.String()+"/retire", nil); status != http.StatusNotFound {
		t.Errorf("retiring another site's device: %d, want 404", status)
	}

	// A command naming a device out of reach queues nothing at all.
	status, body := f.site.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{f.inDevice.String(), f.outDevice.String()}, "type": "refresh_inventory"})
	if status != http.StatusNotFound {
		t.Fatalf("queue across sites: %d %s", status, body)
	}
	_, body = f.fleet.do(http.MethodGet, "/commands", nil)
	if strings.Contains(string(body), f.inDevice.String()) {
		t.Error("a refused request must not have queued anything")
	}
	if status, body := f.site.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{f.inDevice.String()}, "type": "refresh_inventory"}); status != http.StatusCreated {
		t.Fatalf("queue for own device: %d %s", status, body)
	}

	// The dashboard counts their devices only.
	_, body = f.site.do(http.MethodGet, "/dashboard", nil)
	var dash struct {
		Devices struct {
			Total int `json:"total"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &dash); err != nil || dash.Devices.Total != 1 {
		t.Errorf("dashboard total = %d (%v): %s", dash.Devices.Total, err, body)
	}
}

func TestAScopedAdminWorksWithinTheirGroupsOnly(t *testing.T) {
	f := newScopedFixture(t)

	_, body := f.site.do(http.MethodGet, "/groups", nil)
	if !strings.Contains(string(body), "Site A") || strings.Contains(string(body), "Site B") {
		t.Errorf("group list: %s", body)
	}
	if status, _ := f.site.do(http.MethodGet, "/groups/"+f.outGroup+"/members", nil); status != http.StatusNotFound {
		t.Errorf("another site's group: %d, want 404", status)
	}

	status, body := f.fleet.do(http.MethodPost, "/scripts", map[string]any{"name": "Clean temp", "body": "Remove-Item $env:TEMP\\* -Recurse"})
	if status != http.StatusCreated {
		t.Fatalf("create script: %d %s", status, body)
	}
	script := decodeJSON[map[string]any](t, body)["id"].(string)

	// Scripts are readable, and assignable to their own group only.
	if status, _ := f.site.do(http.MethodGet, "/scripts/"+script, nil); status != http.StatusOK {
		t.Errorf("reading a definition: %d", status)
	}
	assign := func(group string) int {
		status, _ := f.site.do(http.MethodPost, "/assignments", map[string]any{
			"item_kind": "script", "item_id": script, "group_id": group, "mode": "include"})
		return status
	}
	if got := assign(f.outGroup); got != http.StatusNotFound {
		t.Errorf("assigning to another site's group: %d, want 404", got)
	}
	if got := assign(f.inGroup); got != http.StatusCreated {
		t.Errorf("assigning to their own group: %d, want 201", got)
	}

	// What concerns the whole fleet is refused outright.
	for _, call := range []struct{ method, path string }{
		{http.MethodPost, "/scripts"}, {http.MethodPost, "/groups"}, {http.MethodGet, "/audit"},
		{http.MethodGet, "/tokens"}, {http.MethodGet, "/notification-channels"}, {http.MethodGet, "/admins"},
		{http.MethodPut, "/admins/" + f.siteID + "/scope"},
	} {
		status, body := f.site.do(call.method, call.path, map[string]any{"group_ids": nil})
		if status != http.StatusForbidden {
			t.Errorf("%s %s as a scoped admin: %d %s", call.method, call.path, status, body)
		}
	}
}

// Somebody must always be able to manage the whole fleet.
func TestTheLastFleetAdminCannotBeScoped(t *testing.T) {
	a, srv := newTestApp(t)
	fleet := signedIn(t, a, srv, store.RoleAdmin)
	_, body := fleet.do(http.MethodGet, "/session", nil)
	var session struct {
		Admin struct {
			ID string `json:"id"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	me := session.Admin.ID
	status, body := fleet.do(http.MethodPut, "/admins/"+me+"/scope", map[string]any{"group_ids": []string{store.BuiltinGroupID.String()}})
	if status != http.StatusConflict {
		t.Fatalf("scoping the last fleet admin: %d %s", status, body)
	}
}

// A token acts with its maker's scope as it is now, not as it was when the
// token was made.
func TestATokenFollowsItsMakersScope(t *testing.T) {
	a, srv := newTestApp(t)
	fleet := signedIn(t, a, srv, store.RoleAdmin)
	enrollDevice(t, a, srv, "ANY-PC")
	maker := seedAdmin(t, a, "maker@example.com", testPassword, store.RoleAdmin)
	makerClient := newAdminClient(t, a, srv)
	if status, body := makerClient.login("maker@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	tok := makeToken(t, makerClient, "reporting", store.RoleReadOnly)
	if _, body := bearer(t, a, srv, tok.Token, http.MethodGet, "/devices", nil); !strings.Contains(string(body), "ANY-PC") {
		t.Fatalf("before scoping: %s", body)
	}
	status, body := fleet.do(http.MethodPost, "/groups", map[string]any{"name": "Empty site", "kind": "static"})
	if status != http.StatusCreated {
		t.Fatalf("create group: %d %s", status, body)
	}
	empty := decodeJSON[map[string]any](t, body)["id"].(string)
	if status, body := fleet.do(http.MethodPut, "/admins/"+maker.ID.String()+"/scope",
		map[string]any{"group_ids": []string{empty}}); status != http.StatusNoContent {
		t.Fatalf("scope the maker: %d %s", status, body)
	}
	if _, body := bearer(t, a, srv, tok.Token, http.MethodGet, "/devices", nil); strings.Contains(string(body), "ANY-PC") {
		t.Errorf("after scoping the maker, the token should see nothing: %s", body)
	}
}
