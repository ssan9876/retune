package app_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// TestWiFiPassphraseIsSealed: a Wi-Fi passphrase is stored sealed, never
// shown to an admin again, handed to an assigned device in the clear, and
// kept across an edit that leaves it alone.
func TestWiFiPassphraseIsSealed(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "LAPTOP-WIFI")
	const secret = "correct horse battery"

	wifi := map[string]any{"kind": "wifi", "ssid": "Contoso Corp", "security": "wpa2_personal", "passphrase": secret}
	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Office Wi-Fi", "settings": []map[string]any{wifi},
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	if strings.Contains(string(body), secret) || !strings.Contains(string(body), `"secret_set":true`) {
		t.Fatalf("the create response shows the passphrase or doesn't say it is set: %s", body)
	}
	profile := decodeJSON[profileResp](t, body)

	for _, path := range []string{"/profiles/" + profile.ID, "/profiles/" + profile.ID + "/versions"} {
		_, body := admin.do(http.MethodGet, path, nil)
		if strings.Contains(string(body), secret) || strings.Contains(string(body), "sealed_secret") ||
			!strings.Contains(string(body), `"secret_set":true`) {
			t.Fatalf("%s leaks or loses the secret: %s", path, body)
		}
	}
	stored, err := a.Store.Q().GetProfileVersion(context.Background(), store.DefaultTenantID, mustUUID(t, profile.ID), 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored.Settings), secret) || !strings.Contains(string(stored.Settings), "sealed_secret") {
		t.Fatalf("stored settings = %s", stored.Settings)
	}

	assignProfile(t, admin, profile.ID, true)
	url := fmt.Sprintf("%s/api/agent/v1/profiles/%s/versions/1", srv.URL, profile.ID)
	status, body = send(t, agent, http.MethodGet, url, nil)
	if status != http.StatusOK {
		t.Fatalf("agent fetch: %d %s", status, body)
	}
	v := decodeJSON[protocol.ProfileVersionResponse](t, body)
	if len(v.Settings) != 1 || v.Settings[0].Passphrase != secret || v.Settings[0].SealedSecret != nil {
		t.Fatalf("the agent got %+v", v.Settings)
	}

	// Renaming, with the passphrase left blank as the console sends it: the
	// secret stays and there is no new version.
	blank := map[string]any{"kind": "wifi", "ssid": "Contoso Corp", "security": "wpa2_personal"}
	status, body = admin.do(http.MethodPost, "/profiles/"+profile.ID, map[string]any{
		"name": "Office Wi-Fi (HQ)", "settings": []map[string]any{blank},
	})
	if status != http.StatusOK {
		t.Fatalf("rename: %d %s", status, body)
	}
	if got := decodeJSON[profileResp](t, body).CurrentVersion; got != 1 {
		t.Fatalf("a rename made version %d", got)
	}
	// A new passphrase is a new version.
	wifi["passphrase"] = "a brand new passphrase"
	_, body = admin.do(http.MethodPost, "/profiles/"+profile.ID, map[string]any{
		"name": "Office Wi-Fi (HQ)", "settings": []map[string]any{wifi},
	})
	if got := decodeJSON[profileResp](t, body).CurrentVersion; got != 2 {
		t.Fatalf("a new passphrase made version %d", got)
	}

	// A new profile can't borrow a secret it never had.
	if status, _ := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Borrower", "settings": []map[string]any{blank},
	}); status != http.StatusBadRequest {
		t.Fatalf("a personal network with no passphrase: %d", status)
	}
	// Nor smuggle in a sealed secret of its own making.
	forged := map[string]any{"kind": "wifi", "ssid": "Contoso Corp", "security": "wpa2_personal",
		"sealed_secret": map[string]any{"ciphertext": "AAAA", "nonce": "AAAA", "mac": "AAAA"}}
	if status, _ := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Forger", "settings": []map[string]any{forged},
	}); status != http.StatusBadRequest {
		t.Fatalf("a client-made sealed secret: %d", status)
	}

	// A device without Wi-Fi reports the setting not applicable, and the
	// profile counts as done.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/profiles/"+profile.ID+"/status",
		protocol.ProfileStatus{Version: 1, Settings: []protocol.SettingResult{
			{Identity: "wifi:Contoso Corp", Status: protocol.SettingNotApplicable, Detail: "no wireless adapter"},
		}})
	if status != http.StatusNoContent {
		t.Fatalf("status report: %d %s", status, body)
	}
	_, body = admin.do(http.MethodGet, "/items/profile/"+profile.ID+"/status", nil)
	if resp := decodeJSON[itemStatusResp](t, body); resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("rollup = %v", resp.Rollup)
	}
}

func TestVPNProfileValidates(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	good := map[string]any{"kind": "vpn", "name": "Contoso VPN", "server": "vpn.contoso.com",
		"tunnel": "ikev2", "authentication": "machine_certificate", "dns_suffix": "corp.contoso.com"}
	if status, body := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "VPN", "settings": []map[string]any{good},
	}); status != http.StatusCreated {
		t.Fatalf("vpn: %d %s", status, body)
	}
	bad := map[string]any{"kind": "vpn", "name": "x'; Remove-Item C:\\ #", "server": "vpn.contoso.com",
		"tunnel": "ikev2", "authentication": "eap"}
	if status, _ := admin.do(http.MethodPost, "/profiles", map[string]any{
		"name": "Injected", "settings": []map[string]any{bad},
	}); status != http.StatusBadRequest {
		t.Fatalf("a name with script in it: %d", status)
	}
}

// An 802.1X network carries no secret: it is stored and sent as given.
func TestEnterpriseWiFiProfile(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	wifi := map[string]any{"kind": "wifi", "ssid": "Contoso Secure", "security": "wpa2_enterprise",
		"eap_method": "tls", "auth_mode": "machine", "server_names": []string{"radius.contoso.com"},
		"trusted_root_thumbprints": []string{"a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"}}
	status, body := admin.do(http.MethodPost, "/profiles", map[string]any{"name": "Secure Wi-Fi", "settings": []map[string]any{wifi}})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"eap_method":"tls"`) || strings.Contains(string(body), `"secret_set":true`) {
		t.Fatalf("created = %s", body)
	}
	delete(wifi, "trusted_root_thumbprints")
	if status, body := admin.do(http.MethodPost, "/profiles", map[string]any{"name": "Unchecked", "settings": []map[string]any{wifi}}); status != http.StatusBadRequest {
		t.Fatalf("no trusted root: %d %s", status, body)
	}
}
