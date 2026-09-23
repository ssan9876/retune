package app_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/store"
)

// TestOperationsSigning: with OPERATIONS_KEYS set, the server refuses
// unsigned scripts and wipe orders at once, and hands signatures on to
// agents, which are what enforce them.
func TestOperationsSigning(t *testing.T) {
	ops, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, srv := newTestAppWith(t, func(c *config.Server) { c.OperationsKeys = []release.PublicKey{ops.Public()} })
	admin := signedIn(t, a, srv, store.RoleAdmin)
	id, agent := enrollDevice(t, a, srv, "PC-SIGNED")

	code, body := admin.do(http.MethodGet, "/session", nil)
	if code != http.StatusOK || !decodeJSON[struct {
		SigningRequired bool `json:"signing_required"`
	}](t, body).SigningRequired {
		t.Fatalf("session: %d %s", code, body)
	}

	// Scripts.
	if code, _ := admin.do(http.MethodPost, "/scripts", map[string]any{"name": "Fix", "body": "Get-Date"}); code != http.StatusBadRequest {
		t.Fatalf("unsigned script: %d", code)
	}
	sig := opsign.Sign(ops, opsign.ScriptManifest("Get-Date", ""))
	code, body = admin.do(http.MethodPost, "/scripts", map[string]any{"name": "Fix", "body": "Get-Date", "signature": sig})
	if code != http.StatusCreated {
		t.Fatalf("signed script: %d %s", code, body)
	}
	scriptID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "script", "item_id": scriptID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	code, body = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/scripts/"+scriptID+"/versions/1", nil)
	if code != http.StatusOK {
		t.Fatalf("agent fetch: %d %s", code, body)
	}
	v := decodeJSON[protocol.ScriptVersionResponse](t, body)
	if v.Signature == nil || v.Signature.Signature != sig.Signature {
		t.Fatalf("the agent didn't get the signature: %+v", v)
	}
	// Renaming keeps the signature, and makes no new version.
	code, body = admin.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{"name": "Fix spooler", "body": "Get-Date"})
	if code != http.StatusOK {
		t.Fatalf("rename: %d %s", code, body)
	}
	if got := decodeJSON[struct {
		CurrentVersion int `json:"current_version"`
	}](t, body).CurrentVersion; got != 1 {
		t.Fatalf("a rename made version %d", got)
	}
	// A body changed without re-signing is refused.
	if code, _ := admin.do(http.MethodPost, "/scripts/"+scriptID, map[string]any{
		"name": "Fix", "body": "Get-Date; Remove-Item C:\\", "signature": sig,
	}); code != http.StatusBadRequest {
		t.Fatalf("re-bodied script: %d", code)
	}

	// Ad-hoc PowerShell.
	device := id.String()
	if code, _ := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{device}, "type": "run_powershell", "script": "Get-Date",
	}); code != http.StatusBadRequest {
		t.Fatalf("unsigned run_powershell: %d", code)
	}
	if code, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{device}, "type": "run_powershell", "script": "Get-Date", "signature": sig,
	}); code != http.StatusCreated {
		t.Fatalf("signed run_powershell: %d %s", code, body)
	}

	// Wipes.
	wipe := func(order map[string]any) (int, []byte) {
		req := map[string]any{"device_ids": []string{device}, "type": "wipe", "confirm_hostname": "PC-SIGNED", "reason": "lost"}
		for k, v := range order {
			req[k] = v
		}
		return admin.do(http.MethodPost, "/commands", req)
	}
	if code, _ := wipe(nil); code != http.StatusBadRequest {
		t.Fatalf("unsigned wipe: %d", code)
	}
	exp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	otherDevice := opsign.Sign(ops, opsign.WipeManifest("00000000-0000-0000-0000-00000000dead", false, exp))
	if code, _ := wipe(map[string]any{"expires": exp, "signature": otherDevice}); code != http.StatusBadRequest {
		t.Fatalf("another device's order: %d", code)
	}
	far := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if code, _ := wipe(map[string]any{"expires": far, "signature": opsign.Sign(ops, opsign.WipeManifest(device, false, far))}); code != http.StatusBadRequest {
		t.Fatalf("a two-day order: %d", code)
	}
	good := opsign.Sign(ops, opsign.WipeManifest(device, false, exp))
	code, body = wipe(map[string]any{"expires": exp, "signature": good})
	if code != http.StatusCreated {
		t.Fatalf("signed wipe: %d %s", code, body)
	}
	cmdID := decodeJSON[queuedResp](t, body).Commands[0].ID
	c, _, err := a.Commands.Get(context.Background(), mustUUID(t, cmdID))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(exp) {
		t.Fatalf("the command expires %v, the order %v", c.ExpiresAt, exp)
	}
}

// TestSignaturesPassThroughWithoutServerKeys: a server without
// OPERATIONS_KEYS doesn't check, but still hands a signature on, for agents
// that require one.
func TestSignaturesPassThroughWithoutServerKeys(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "PC-PLAIN")
	ops, _ := release.GenerateKey()
	sig := opsign.Sign(ops, opsign.ScriptManifest("Get-Date", ""))

	if code, _ := admin.do(http.MethodPost, "/scripts", map[string]any{"name": "Unsigned", "body": "Get-Date"}); code != http.StatusCreated {
		t.Fatalf("unsigned script: %d", code)
	}
	code, body := admin.do(http.MethodPost, "/scripts", map[string]any{"name": "Signed", "body": "Get-Date", "signature": sig})
	if code != http.StatusCreated {
		t.Fatalf("signed script: %d %s", code, body)
	}
	scriptID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "script", "item_id": scriptID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	_, body = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/scripts/"+scriptID+"/versions/1", nil)
	if v := decodeJSON[protocol.ScriptVersionResponse](t, body); v.Signature == nil {
		t.Fatalf("the signature was dropped: %s", body)
	}
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
