package app_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/store"
)

// enrollAs enrolls a device claiming a serial number, with a given token.
func enrollAs(t *testing.T, a *app.App, srv *httptest.Server, token, hostname, serial string) (int, protocol.EnrollResponse) {
	t.Helper()
	_, csrPEM := newKeyAndCSR(t)
	status, body := send(t, httpClient(a, nil), http.MethodPost, srv.URL+"/api/agent/v1/enroll",
		protocol.EnrollRequest{Token: token, CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: hostname, Serial: serial}})
	var resp protocol.EnrollResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
	}
	return status, resp
}

// TestZeroTouchProvisioning: devices registered by serial join their groups
// and get their names when they enroll, and a registered-only token enrolls
// nothing else.
func TestZeroTouchProvisioning(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.do(http.MethodPost, "/groups", map[string]any{"name": "Sales laptops", "kind": "static"})
	if status != http.StatusCreated {
		t.Fatalf("create group: %d %s", status, body)
	}
	groupID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID

	// A CSV with any problem imports nothing, and says what every problem is.
	bad := "serial,name,groups\nSN-001,SALES-01,Sales laptops\nSN-002,not a name!,Sales laptops\nSN-003,,Nobody's group\nsn-001,,\n"
	status, body = admin.do(http.MethodPost, "/device-registrations/import", map[string]any{"csv": bad})
	if status != http.StatusBadRequest {
		t.Fatalf("a bad import: %d %s", status, body)
	}
	problems := decodeJSON[struct {
		Problems []struct {
			Line    int    `json:"line"`
			Message string `json:"message"`
		} `json:"problems"`
	}](t, body).Problems
	if len(problems) != 3 || problems[0].Line != 3 || problems[1].Line != 4 || problems[2].Line != 5 {
		t.Fatalf("problems = %+v", problems)
	}
	if _, body := admin.do(http.MethodGet, "/device-registrations", nil); !strings.Contains(string(body), `"total":0`) {
		t.Fatalf("a failed import registered something: %s", body)
	}
	good := "serial,name,groups\nSN-001,SALES-01,Sales laptops\nSN-002,,\n"
	if status, body := admin.do(http.MethodPost, "/device-registrations/import", map[string]any{"csv": good}); status != http.StatusCreated ||
		!strings.Contains(string(body), `"created":2`) {
		t.Fatalf("import: %d %s", status, body)
	}
	if status, _ := admin.do(http.MethodPost, "/device-registrations", map[string]any{"serial": "sn-002"}); status != http.StatusConflict {
		t.Fatalf("a serial registered twice, in another case: %d", status)
	}
	if status, body := admin.do(http.MethodPost, "/device-registrations", map[string]any{
		"serial": "SN-009", "group_ids": []string{store.BuiltinGroupID.String()},
	}); status != http.StatusBadRequest || !strings.Contains(string(body), "static") {
		t.Fatalf("registered into All devices: %d %s", status, body)
	}

	// A registered-only token enrolls registered serials only.
	status, body = admin.do(http.MethodPost, "/tokens", map[string]any{"label": "Sales rollout", "registered_only": true})
	if status != http.StatusCreated || !strings.Contains(string(body), `"registered_only":true`) {
		t.Fatalf("create token: %d %s", status, body)
	}
	token := decodeJSON[struct {
		Token string `json:"token"`
	}](t, body).Token
	if status, _ := enrollAs(t, a, srv, token, "DESKTOP-RANDOM", "SN-404"); status != http.StatusForbidden {
		t.Fatalf("an unregistered serial with a registered-only token: %d", status)
	}
	status, enrolled := enrollAs(t, a, srv, token, "DESKTOP-AB12CD", "sn-001")
	if status != http.StatusOK {
		t.Fatalf("a registered serial: %d", status)
	}

	// It joined its group, and has been told to rename itself.
	_, body = admin.do(http.MethodGet, "/groups/"+groupID+"/members", nil)
	if !strings.Contains(string(body), enrolled.DeviceID) {
		t.Fatalf("the device isn't in its group: %s", body)
	}
	_, body = admin.do(http.MethodGet, "/commands?device_id="+enrolled.DeviceID, nil)
	if !strings.Contains(string(body), `"type":"rename_computer"`) || !strings.Contains(string(body), "SALES-01") {
		t.Fatalf("no rename queued: %s", body)
	}
	_, body = admin.do(http.MethodGet, "/device-registrations", nil)
	if !strings.Contains(string(body), `"device_id":"`+enrolled.DeviceID+`"`) {
		t.Fatalf("the registration doesn't say which device it became: %s", body)
	}

	// A registration is spent while its device is active: quoting the same
	// serial doesn't enroll a second machine into its groups. Once the first
	// is retired - after a reimage - the registration works again.
	if status, _ := enrollAs(t, a, srv, token, "ROGUE", "SN-001"); status != http.StatusForbidden {
		t.Fatalf("a spent registration with a registered-only token: %d, want 403", status)
	}
	if status, body := admin.do(http.MethodPost, "/devices/"+enrolled.DeviceID+"/retire", nil); status != http.StatusNoContent {
		t.Fatalf("retire: %d %s", status, body)
	}
	status, reimaged := enrollAs(t, a, srv, token, "DESKTOP-AB12CD", "sn-001")
	if status != http.StatusOK {
		t.Fatalf("the registration after its device was retired: %d", status)
	}
	_, body = admin.do(http.MethodGet, "/groups/"+groupID+"/members", nil)
	if !strings.Contains(string(body), reimaged.DeviceID) {
		t.Fatalf("the reimaged device isn't in its group: %s", body)
	}

	// A device registered with no name keeps its own, and an ordinary token
	// still enrolls anything.
	status, second := enrollAs(t, a, srv, token, "DESKTOP-XY98", "SN-002")
	if status != http.StatusOK {
		t.Fatalf("second registered device: %d", status)
	}
	if _, body := admin.do(http.MethodGet, "/commands?device_id="+second.DeviceID, nil); strings.Contains(string(body), "rename_computer") {
		t.Fatalf("a device registered without a name was renamed: %s", body)
	}
	status, body = admin.do(http.MethodPost, "/tokens", map[string]any{"label": "Anything"})
	if status != http.StatusCreated {
		t.Fatalf("create open token: %d %s", status, body)
	}
	open := decodeJSON[struct {
		Token string `json:"token"`
	}](t, body).Token
	if status, _ := enrollAs(t, a, srv, open, "DESKTOP-OTHER", "SN-777"); status != http.StatusOK {
		t.Fatalf("an ordinary token: %d", status)
	}

	// Renaming by hand is an admin's command, validated.
	if status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{second.DeviceID}, "type": "rename_computer", "name": "bad name",
	}); status != http.StatusBadRequest {
		t.Fatalf("a bad name: %d %s", status, body)
	}
	if status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{second.DeviceID}, "type": "rename_computer", "name": "SALES-02", "restart": true,
	}); status != http.StatusCreated {
		t.Fatalf("rename: %d %s", status, body)
	}
}
