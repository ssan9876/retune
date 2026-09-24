package app_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/attest"
	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

// TestConditionalAccess: network access control and identity providers can
// ask whether a device is compliant, and a device can get a signed statement
// of it, bound to its certificate.
func TestConditionalAccess(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.do(http.MethodPost, "/compliance-policies", map[string]any{
		"name": "No reboot pending", "rules": json.RawMessage(`[{"type":"no_pending_reboot"}]`),
	})
	if status != http.StatusCreated {
		t.Fatalf("create policy: %d %s", status, body)
	}
	policyID := decodeJSON[struct {
		ID string `json:"id"`
	}](t, body).ID
	if status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": compliance.ItemKindCompliance, "item_id": policyID, "group_id": store.BuiltinGroupID.String(), "mode": "include",
	}); status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	good, goodAgent := enrollDevice(t, a, srv, "PC-GOOD")
	bad, badAgent := enrollDevice(t, a, srv, "PC-BAD")
	for agent, inv := range map[*http.Client]protocol.Inventory{
		goodAgent: {Hostname: "PC-GOOD", NetworkAdapters: []protocol.NetworkAdapter{{Name: "Wi-Fi", MAC: "00:15:5D:01:02:03"}}},
		badAgent:  {Hostname: "PC-BAD", PendingReboot: true, NetworkAdapters: []protocol.NetworkAdapter{{Name: "Ethernet", MAC: "00:15:5D:0A:0B:0C"}}},
	} {
		if status, body := send(t, agent, http.MethodPut, srv.URL+"/api/agent/v1/inventory", inv); status != http.StatusOK {
			t.Fatalf("inventory: %d %s", status, body)
		}
	}

	type answer struct {
		Items []attest.DeviceCompliance `json:"items"`
	}
	lookup := func(query string) answer {
		t.Helper()
		status, body := admin.do(http.MethodGet, "/compliance/devices?"+query, nil)
		if status != http.StatusOK {
			t.Fatalf("lookup %s: %d %s", query, status, body)
		}
		return decodeJSON[answer](t, body)
	}
	// A MAC in any common format.
	for _, mac := range []string{"00-15-5d-01-02-03", "00155D010203", "0015.5d01.0203"} {
		got := lookup("mac=" + mac)
		if len(got.Items) != 1 || got.Items[0].DeviceID != good.String() || !got.Items[0].Compliant || got.Items[0].Compliance != "compliant" {
			t.Fatalf("mac %s: %+v", mac, got)
		}
	}
	if got := lookup("hostname=pc-bad"); len(got.Items) != 1 || got.Items[0].Compliant || got.Items[0].Compliance != "non_compliant" {
		t.Fatalf("the non-compliant device: %+v", got)
	}
	if got := lookup("device_id=" + bad.String()); len(got.Items) != 1 || got.Items[0].Hostname != "PC-BAD" {
		t.Fatalf("by device id: %+v", got)
	}
	if got := lookup("mac=11:22:33:44:55:66"); len(got.Items) != 0 {
		t.Fatalf("an unknown MAC: %+v", got)
	}
	for _, q := range []string{"", "mac=00155D010203&hostname=PC-GOOD"} {
		if status, _ := admin.do(http.MethodGet, "/compliance/devices?"+q, nil); status != http.StatusBadRequest {
			t.Errorf("query %q: %d, want 400", q, status)
		}
	}
	// What a NAC would use: a read-only token.
	tok := makeToken(t, admin, "clearpass", store.RoleReadOnly)
	if status, body := bearer(t, a, srv, tok.Token, http.MethodGet, "/compliance/devices?mac=00:15:5D:01:02:03", nil); status != http.StatusOK ||
		!strings.Contains(string(body), `"compliant":true`) {
		t.Fatalf("a read-only token: %d %s", status, body)
	}

	// The device's own statement, bound to its certificate.
	status, body = send(t, goodAgent, http.MethodGet, srv.URL+"/api/agent/v1/compliance-statement", nil)
	if status != http.StatusOK {
		t.Fatalf("statement: %d %s", status, body)
	}
	resp := decodeJSON[protocol.ComplianceStatementResponse](t, body)
	var claims attest.Claims
	if err := a.CA.VerifyJWT(resp.Token, &claims); err != nil {
		t.Fatal(err)
	}
	cert := goodAgent.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
	sum := sha256.Sum256(cert)
	if claims.Subject != good.String() || !claims.Compliant || claims.Audience != attest.Audience ||
		claims.Expires <= claims.IssuedAt || claims.Confirmation == nil ||
		claims.Confirmation.CertThumbprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("claims = %+v", claims)
	}
	_, body = send(t, badAgent, http.MethodGet, srv.URL+"/api/agent/v1/compliance-statement", nil)
	if err := a.CA.VerifyJWT(decodeJSON[protocol.ComplianceStatementResponse](t, body).Token, &claims); err != nil || claims.Compliant {
		t.Fatalf("the non-compliant device's statement: %+v, %v", claims, err)
	}

	// The key to check them with is public.
	res, err := httpClient(a, nil).Get(srv.URL + "/api/admin/v1/compliance/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil || res.StatusCode != http.StatusOK || len(jwks.Keys) != 1 ||
		jwks.Keys[0]["kid"] != a.CA.KeyID() || jwks.Keys[0]["alg"] != "ES256" {
		t.Fatalf("jwks: %d %+v %v", res.StatusCode, jwks, err)
	}
}
