package app_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

const recoveryPassword = "123456-234567-345678-456789-567890-678901-789012-890123"

type keyResp struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	VolumeID string `json:"volume_id"`
	Method   string `json:"method"`
}

func TestBitLockerEscrowAndReveal(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	deviceID, agent := enrollDevice(t, a, srv, "LAPTOP-ENCRYPTED")

	// Before anything is escrowed the agent is told so, which is how it knows
	// it still has work to do.
	status, body := send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/bitlocker?volume_id=C:", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	if decodeJSON[protocol.BitLockerHasResponse](t, body).Escrowed {
		t.Fatal("nothing is escrowed yet")
	}

	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/bitlocker",
		protocol.BitLockerEscrowRequest{
			VolumeID: "C:", Method: protocol.XtsAes256, RecoveryPassword: recoveryPassword,
		})
	if status != http.StatusNoContent {
		t.Fatalf("escrow: %d %s", status, body)
	}

	status, body = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/bitlocker?volume_id=C:", nil)
	if status != http.StatusOK || !decodeJSON[protocol.BitLockerHasResponse](t, body).Escrowed {
		t.Fatalf("the server should now hold a key: %d %s", status, body)
	}

	// The listing shows the volume but never the key.
	status, body = admin.do(http.MethodGet, "/devices/"+deviceID.String()+"/bitlocker-keys", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	if strings.Contains(string(body), "123456") {
		t.Fatalf("a listing must not contain the recovery key: %s", body)
	}
	list := decodeJSON[struct {
		Items []keyResp `json:"items"`
	}](t, body)
	if len(list.Items) != 1 || list.Items[0].VolumeID != "C:" || list.Items[0].Hostname != "LAPTOP-ENCRYPTED" {
		t.Fatalf("items = %+v", list.Items)
	}

	// Revealing it hands the key over, once, deliberately.
	status, body = admin.do(http.MethodPost, "/bitlocker-keys/"+list.Items[0].ID+"/reveal",
		map[string]string{"reason": "help desk call 1234"})
	if status != http.StatusOK {
		t.Fatalf("reveal: %d %s", status, body)
	}
	revealed := decodeJSON[struct {
		RecoveryPassword string `json:"recovery_password"`
		VolumeID         string `json:"volume_id"`
	}](t, body)
	if revealed.RecoveryPassword != recoveryPassword {
		t.Fatalf("revealed %q", revealed.RecoveryPassword)
	}

	// And it is on the record.
	status, body = admin.do(http.MethodGet, "/audit", nil)
	if status != http.StatusOK {
		t.Fatalf("audit: %d %s", status, body)
	}
	if !strings.Contains(string(body), "bitlocker_key.viewed") {
		t.Fatal("revealing a recovery key must be audited")
	}
	if !strings.Contains(string(body), "help desk call 1234") {
		t.Error("the reason should be recorded")
	}
	if strings.Contains(string(body), "123456-234567") {
		t.Fatal("the recovery key must never appear in the audit log")
	}
}

// A read-only admin can see that a key exists but cannot have it.
func TestReadOnlyAdminCannotRevealAKey(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	deviceID, agent := enrollDevice(t, a, srv, "LAPTOP-ENCRYPTED")

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/bitlocker",
		protocol.BitLockerEscrowRequest{
			VolumeID: "C:", Method: protocol.XtsAes256, RecoveryPassword: recoveryPassword,
		})
	if status != http.StatusNoContent {
		t.Fatalf("escrow: %d %s", status, body)
	}
	status, body = admin.do(http.MethodGet, "/devices/"+deviceID.String()+"/bitlocker-keys", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	key := decodeJSON[struct {
		Items []keyResp `json:"items"`
	}](t, body).Items[0]

	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := viewer.do(http.MethodGet, "/devices/"+deviceID.String()+"/bitlocker-keys", nil); status != http.StatusOK {
		t.Error("a read-only admin should see which volumes have a key")
	}
	status, body = viewer.do(http.MethodPost, "/bitlocker-keys/"+key.ID+"/reveal", map[string]string{})
	if status != http.StatusForbidden {
		t.Fatalf("a read-only admin must not be able to reveal a key, got %d %s", status, body)
	}
	if strings.Contains(string(body), "123456") {
		t.Fatal("the refusal must not contain the key either")
	}
}

// One device must not be able to read another's escrowed key: the endpoint only
// ever answers for the calling device.
func TestADeviceOnlySeesItsOwnEscrowState(t *testing.T) {
	a, srv := newTestApp(t)
	_, first := enrollDevice(t, a, srv, "LAPTOP-ONE")
	_, second := enrollDevice(t, a, srv, "LAPTOP-TWO")

	status, body := send(t, first, http.MethodPost, srv.URL+"/api/agent/v1/bitlocker",
		protocol.BitLockerEscrowRequest{
			VolumeID: "C:", Method: protocol.XtsAes256, RecoveryPassword: recoveryPassword,
		})
	if status != http.StatusNoContent {
		t.Fatalf("escrow: %d %s", status, body)
	}

	url := srv.URL + "/api/agent/v1/bitlocker?volume_id=C:"
	status, body = send(t, second, http.MethodGet, url, nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	if decodeJSON[protocol.BitLockerHasResponse](t, body).Escrowed {
		t.Fatal("another device's key is not this device's key")
	}
}

func TestEscrowRejectsNonsense(t *testing.T) {
	a, srv := newTestApp(t)
	_, agent := enrollDevice(t, a, srv, "LAPTOP")

	status, _ := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/bitlocker",
		protocol.BitLockerEscrowRequest{VolumeID: "", RecoveryPassword: recoveryPassword})
	if status != http.StatusBadRequest {
		t.Errorf("a key with no volume should be refused, got %d", status)
	}

	status, _ = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/bitlocker", nil)
	if status != http.StatusBadRequest {
		t.Errorf("asking without a volume should be refused, got %d", status)
	}
}

func TestRevealMissingKeyIsNotFound(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	missing := "01a09bae-0000-7000-8000-00000000dead"
	status, _ := admin.do(http.MethodPost, fmt.Sprintf("/bitlocker-keys/%s/reveal", missing), map[string]string{})
	if status != http.StatusNotFound {
		t.Fatalf("want 404, got %d", status)
	}
}
