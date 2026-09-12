package app_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
)

func TestInventoryEndpoint(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-INV")
	base := srv.URL + "/api/agent/v1"

	status, body := send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	resp := decodeJSON[protocol.CheckinResponse](t, body)
	if status != http.StatusOK || !resp.InventoryDue {
		t.Fatalf("first check-in: %d %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"commands":[]`)) {
		t.Fatalf("commands must be an empty array, got %s", body)
	}

	inv := protocol.Inventory{
		Hostname: "PC-INV",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", RAMBytes: 8 << 30},
		Software: []protocol.Software{{Name: "App", Version: "1", Scope: "machine"}},
	}
	status, body = send(t, mtls, http.MethodPut, base+"/inventory", inv)
	if status != http.StatusOK {
		t.Fatalf("inventory: %d %s", status, body)
	}
	hash := decodeJSON[protocol.InventoryResponse](t, body).Hash
	if hash != protocol.InventoryHash(inv) {
		t.Fatalf("hash = %s", hash)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, id); d.Manufacturer != "Contoso" {
		t.Fatalf("device not refreshed from inventory: %+v", d)
	}

	_, body = send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{InventoryHash: hash})
	if decodeJSON[protocol.CheckinResponse](t, body).InventoryDue {
		t.Fatal("inventory must not be due right after an upload")
	}

	big := protocol.Inventory{Hostname: strings.Repeat("a", 9<<20)}
	status, body = send(t, mtls, http.MethodPut, base+"/inventory", big)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", status, body)
	}
}

func TestCommandEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-CMD")
	base := srv.URL + "/api/agent/v1"

	c, err := a.Commands.Queue(ctx, commands.QueueOptions{
		DeviceID: id, Type: protocol.CommandRefreshInventory, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	got := decodeJSON[protocol.CheckinResponse](t, body).Commands
	if len(got) != 1 || got[0].ID != c.ID.String() || got[0].Type != protocol.CommandRefreshInventory {
		t.Fatalf("commands = %+v", got)
	}

	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/start", nil); status != http.StatusNoContent {
		t.Fatalf("start: %d %s", status, body)
	}
	result := protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "done"}
	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result", result); status != http.StatusNoContent {
		t.Fatalf("result: %d %s", status, body)
	}
	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result", result); status != http.StatusNoContent {
		t.Fatal("re-submitting a result must succeed")
	}
	if stored, res, _ := a.Commands.Get(ctx, c.ID); stored.Status != "succeeded" || res == nil || res.Stdout != "done" {
		t.Fatalf("stored command = %+v result = %+v", stored, res)
	}

	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/"+uuid.Must(uuid.NewV7()).String()+"/result", result); status != http.StatusNotFound {
		t.Fatal("unknown command must be 404")
	}
	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/not-a-uuid/start", nil); status != http.StatusNotFound {
		t.Fatal("malformed command ID must be 404")
	}
	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result",
		protocol.CommandResult{Status: "weird"}); status != http.StatusBadRequest {
		t.Fatalf("bad status: %d %s", status, body)
	}
}

func TestRenewAndUnenroll(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, oldClient := enrollDevice(t, a, srv, "PC-RENEW")
	base := srv.URL + "/api/agent/v1"
	before, _ := a.Store.Q().GetDevice(ctx, id)

	newKey, csrPEM := newKeyAndCSR(t)
	status, body := send(t, oldClient, http.MethodPost, base+"/renew", protocol.RenewRequest{CSRPEM: csrPEM})
	if status != http.StatusOK {
		t.Fatalf("renew: %d %s", status, body)
	}
	renewed := decodeJSON[protocol.RenewResponse](t, body)
	after, _ := a.Store.Q().GetDevice(ctx, id)
	if after.CertSerial == before.CertSerial || after.PrevCertSerial != before.CertSerial {
		t.Fatalf("device after renew = %+v", after)
	}

	// The old certificate still works until the new one is used.
	if status, _ := send(t, oldClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusOK {
		t.Fatal("superseded certificate must stay valid until the new one is used")
	}
	newClient := clientFor(t, a, newKey, renewed.CertPEM)
	if status, _ := send(t, newClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusOK {
		t.Fatal("renewed certificate must be accepted")
	}
	if cur, _ := a.Store.Q().GetDevice(ctx, id); cur.PrevCertSerial != "" {
		t.Fatalf("prev serial must be cleared once the new certificate is used: %q", cur.PrevCertSerial)
	}
	if status, _ := send(t, oldClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusUnauthorized {
		t.Fatal("superseded certificate must stop working")
	}

	block, _ := pem.Decode([]byte(renewed.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() {
		t.Fatalf("renewed CN = %s", cert.Subject.CommonName)
	}

	if err := a.Devices.Unenroll(ctx, id, "test"); err != nil {
		t.Fatal(err)
	}
	status, body = send(t, newClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	if status != http.StatusGone || !bytes.Contains(body, []byte("device_unenrolled")) {
		t.Fatalf("unenrolled check-in: %d %s", status, body)
	}
}
