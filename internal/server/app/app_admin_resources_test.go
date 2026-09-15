package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

func TestDeviceEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-ADMIN")
	// Give the device inventory so the detail view has something to show.
	inv := protocol.Inventory{
		Hostname: "PC-ADMIN",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Book 9", RAMBytes: 8 << 30},
		Disks:    []protocol.Disk{{Name: "C:", FreeBytes: 100 << 30}},
		Software: []protocol.Software{{Name: "7-Zip", Version: "24.08", Scope: "machine"}},
	}
	if status, body := send(t, mtls, http.MethodPut, srv.URL+"/api/agent/v1/inventory", inv); status != http.StatusOK {
		t.Fatalf("seed inventory: %d %s", status, body)
	}
	c := signedIn(t, a, srv, store.RoleAdmin)

	status, body := c.do(http.MethodGet, "/devices", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("PC-ADMIN")) || !bytes.Contains(body, []byte(`"total":1`)) {
		t.Fatalf("device list: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/devices?search=nothing", nil); !bytes.Contains(body, []byte(`"total":0`)) {
		t.Fatalf("filtered list: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/devices?status=retired", nil); !bytes.Contains(body, []byte(`"total":0`)) {
		t.Fatalf("status filter: %s", body)
	}

	status, body = c.do(http.MethodGet, "/devices/"+id.String(), nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("Contoso")) ||
		!bytes.Contains(body, []byte("7-Zip")) || !bytes.Contains(body, []byte(`"ram_gb":8`)) {
		t.Fatalf("device detail: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/devices/"+uuid.Must(uuid.NewV7()).String(), nil); status != http.StatusNotFound {
		t.Fatalf("unknown device: %d", status)
	}
	if status, _ = c.do(http.MethodGet, "/devices/not-a-uuid", nil); status != http.StatusNotFound {
		t.Fatalf("malformed device id: %d", status)
	}

	status, body = c.do(http.MethodGet, "/devices/"+id.String()+"/software", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("7-Zip")) {
		t.Fatalf("software list: %d %s", status, body)
	}

	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/retire", nil); status != http.StatusNoContent {
		t.Fatalf("retire: %d %s", status, body)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, store.DefaultTenantID, id); d.Status != store.DeviceRetired {
		t.Fatalf("status after retire = %s", d.Status)
	}
	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/retire", nil); status != http.StatusConflict {
		t.Fatalf("retiring twice: %d %s", status, body)
	}
	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/unenroll", nil); status != http.StatusNoContent {
		t.Fatalf("unenroll: %d %s", status, body)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, store.DefaultTenantID, id); d.Status != store.DeviceUnenrolled {
		t.Fatalf("status after unenroll = %s", d.Status)
	}
}

func TestCommandEndpointsAdmin(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	first, _ := enrollDevice(t, a, srv, "PC-1")
	second, _ := enrollDevice(t, a, srv, "PC-2")
	c := signedIn(t, a, srv, store.RoleAdmin)

	// One request queues the same command on two devices.
	status, body := c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids":      []string{first.String(), second.String()},
		"type":            protocol.CommandRunPowerShell,
		"script":          "Get-Date",
		"timeout_seconds": 60,
	})
	if status != http.StatusCreated {
		t.Fatalf("queue: %d %s", status, body)
	}
	var queued struct {
		Commands []struct {
			ID       string `json:"id"`
			DeviceID string `json:"device_id"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || len(queued.Commands) != 2 {
		t.Fatalf("queue response = %s, err = %v", body, err)
	}

	if status, body = c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{first.String()}, "type": "nonsense",
	}); status != http.StatusBadRequest {
		t.Fatalf("bad type: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{}, "type": protocol.CommandRefreshInventory,
	}); status != http.StatusBadRequest {
		t.Fatalf("no devices: %d", status)
	}

	if _, body = c.do(http.MethodGet, "/commands", nil); !bytes.Contains(body, []byte(`"total":2`)) {
		t.Fatalf("command list: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/commands?device_id="+first.String(), nil); !bytes.Contains(body, []byte(`"total":1`)) {
		t.Fatalf("device filter: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/commands?status=queued", nil); !bytes.Contains(body, []byte(`"total":2`)) {
		t.Fatalf("status filter: %s", body)
	}
	if status, _ = c.do(http.MethodGet, "/commands?device_id=not-a-uuid", nil); status != http.StatusBadRequest {
		t.Fatalf("malformed device filter: %d", status)
	}

	cmdID := uuid.MustParse(queued.Commands[0].ID)
	if err := a.Commands.Complete(ctx, first, cmdID, protocol.CommandResult{
		Status: protocol.ResultSucceeded, Stdout: "ran", StartedAt: time.Now(), FinishedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	status, body = c.do(http.MethodGet, "/commands/"+cmdID.String(), nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"stdout":"ran"`)) {
		t.Fatalf("command detail: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/commands/"+uuid.Must(uuid.NewV7()).String(), nil); status != http.StatusNotFound {
		t.Fatalf("unknown command: %d", status)
	}
}

func TestTokenAuditAndAdminEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleAdmin)

	status, body := c.do(http.MethodPost, "/tokens", map[string]any{"label": "office", "max_uses": 5, "expires_in_hours": 24})
	if status != http.StatusCreated || !bytes.Contains(body, []byte(`"token":"rt_`)) {
		t.Fatalf("create token: %d %s", status, body)
	}
	var created struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.CreatedAt.IsZero() || created.ExpiresAt.IsZero() {
		t.Fatalf("token timestamps must be reported: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/tokens", nil); !bytes.Contains(body, []byte("office")) || bytes.Contains(body, []byte("rt_")) {
		t.Fatalf("token list must not contain plaintext tokens: %s", body)
	}
	if status, body = c.do(http.MethodPost, "/tokens/"+created.ID+"/revoke", nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/tokens", nil); !bytes.Contains(body, []byte(`"revoked_at"`)) {
		t.Fatalf("revoked token must show its time: %s", body)
	}
	if status, _ = c.do(http.MethodPost, "/tokens/"+uuid.Must(uuid.NewV7()).String()+"/revoke", nil); status != http.StatusNotFound {
		t.Fatalf("revoking an unknown token: %d", status)
	}

	// Admin management.
	status, body = c.do(http.MethodPost, "/admins", map[string]any{
		"email": "second@example.com", "password": testPassword, "role": store.RoleReadOnly,
	})
	if status != http.StatusCreated || !bytes.Contains(body, []byte("second@example.com")) {
		t.Fatalf("create admin: %d %s", status, body)
	}
	var newAdmin struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &newAdmin); err != nil {
		t.Fatal(err)
	}
	if status, body = c.do(http.MethodPost, "/admins", map[string]any{
		"email": "weak@example.com", "password": "short", "role": store.RoleAdmin,
	}); status != http.StatusBadRequest {
		t.Fatalf("weak password: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/admins", nil); !bytes.Contains(body, []byte("ops@example.com")) ||
		bytes.Contains(body, []byte("password_hash")) || bytes.Contains(body, []byte("totp_secret")) {
		t.Fatalf("admin list must not leak secrets: %s", body)
	}

	if status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/password", map[string]any{"password": "another good password"}); status != http.StatusNoContent {
		t.Fatalf("set password: %d %s", status, body)
	}
	status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/totp", map[string]any{"enabled": true})
	if status != http.StatusOK || !bytes.Contains(body, []byte("otpauth://")) {
		t.Fatalf("enable TOTP: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/totp", map[string]any{"enabled": false}); status != http.StatusNoContent {
		t.Fatalf("disable TOTP: %d", status)
	}
	if status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/disabled", map[string]any{"disabled": true}); status != http.StatusNoContent {
		t.Fatalf("disable admin: %d %s", status, body)
	}
	if cur, _ := a.Store.Q().GetAdmin(ctx, store.DefaultTenantID, uuid.MustParse(newAdmin.ID)); cur.DisabledAt == nil {
		t.Fatal("admin must be disabled")
	}
	// The signed-in admin is the only enabled admin, so disabling them fails.
	me, _ := a.Store.Q().GetAdminByEmail(ctx, "ops@example.com")
	if status, body = c.do(http.MethodPost, "/admins/"+me.ID.String()+"/disabled", map[string]any{"disabled": true}); status != http.StatusConflict {
		t.Fatalf("disabling the last admin: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodPost, "/admins/"+uuid.Must(uuid.NewV7()).String()+"/password", map[string]any{"password": testPassword}); status != http.StatusNotFound {
		t.Fatalf("unknown admin: %d", status)
	}

	if _, body = c.do(http.MethodGet, "/audit", nil); !bytes.Contains(body, []byte("admin.login")) ||
		!bytes.Contains(body, []byte("enrollment_token.created")) {
		t.Fatalf("audit: %s", body)
	}
}

func TestReadOnlyCannotWrite(t *testing.T) {
	a, srv := newTestApp(t)
	id, _ := enrollDevice(t, a, srv, "PC-RO")
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/devices", nil); status != http.StatusOK {
		t.Fatal("read-only must be able to list devices")
	}
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/devices/" + id.String() + "/retire", nil},
		{http.MethodPost, "/devices/" + id.String() + "/unenroll", nil},
		{http.MethodPost, "/commands", map[string]any{"device_ids": []string{id.String()}, "type": protocol.CommandRefreshInventory}},
		{http.MethodPost, "/tokens", map[string]any{"label": "x"}},
		{http.MethodPost, "/admins", map[string]any{"email": "x@example.com", "password": testPassword, "role": store.RoleAdmin}},
	}
	for _, w := range writes {
		if status, body := c.do(w.method, w.path, w.body); status != http.StatusForbidden {
			t.Errorf("%s %s = %d %s, want 403", w.method, w.path, status, body)
		}
	}
}
