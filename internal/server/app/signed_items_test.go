package app_test

import (
	"net/http"
	"testing"

	"retune/internal/config"
	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/store"
)

// TestAppAndProfileSigning: with OPERATIONS_KEYS set, apps and profiles are
// held to it the way scripts are. The signature is checked against exactly
// what an agent will be sent, so one the server accepts is one the agent
// accepts.
func TestAppAndProfileSigning(t *testing.T) {
	ops, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	trusted := []release.PublicKey{ops.Public()}
	a, srv := newTestAppWith(t, func(c *config.Server) { c.OperationsKeys = trusted })
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "PC-SIGNED-ITEMS")
	assign := func(kind, id string) {
		t.Helper()
		if code, body := admin.do(http.MethodPost, "/assignments", map[string]any{
			"item_kind": kind, "item_id": id,
			"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
		}); code != http.StatusCreated {
			t.Fatalf("assign %s: %d %s", kind, code, body)
		}
	}
	type created struct {
		ID             string `json:"id"`
		CurrentVersion int    `json:"current_version"`
		Signed         bool   `json:"signed"`
	}

	// Apps.
	app := map[string]any{"name": "7-Zip", "package_id": "7zip.7zip"}
	if code, _ := admin.do(http.MethodPost, "/apps", app); code != http.StatusBadRequest {
		t.Fatalf("unsigned app: %d", code)
	}
	appSig := opsign.Sign(ops, protocol.AppDefinition{PackageID: "7zip.7zip"}.Manifest())
	app["signature"] = appSig
	code, body := admin.do(http.MethodPost, "/apps", app)
	if code != http.StatusCreated {
		t.Fatalf("signed app: %d %s", code, body)
	}
	got := decodeJSON[created](t, body)
	if !got.Signed {
		t.Errorf("the app should say it is signed: %s", body)
	}
	assign("app", got.ID)
	code, body = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/apps/"+got.ID+"/versions/1", nil)
	if code != http.StatusOK {
		t.Fatalf("agent fetch app: %d %s", code, body)
	}
	v := decodeJSON[protocol.AppVersionResponse](t, body)
	if err := opsign.Verify(trusted, v.Definition().Manifest(), v.Signature); err != nil {
		t.Fatalf("the agent can't verify what it was sent: %v (%+v)", err, v)
	}
	// Renaming keeps the signature and makes no new version.
	code, body = admin.do(http.MethodPost, "/apps/"+got.ID, map[string]any{"name": "7-Zip (x64)", "package_id": "7zip.7zip"})
	if code != http.StatusOK {
		t.Fatalf("rename app: %d %s", code, body)
	}
	if r := decodeJSON[created](t, body); r.CurrentVersion != 1 || !r.Signed {
		t.Fatalf("a rename should keep version 1 and its signature: %s", body)
	}
	// Arguments changed under the old signature are refused.
	if code, _ := admin.do(http.MethodPost, "/apps/"+got.ID, map[string]any{
		"name": "7-Zip", "package_id": "7zip.7zip", "install_args": "--override calc.exe", "signature": appSig,
	}); code != http.StatusBadRequest {
		t.Fatalf("re-argued app: %d", code)
	}

	// Profiles, with a secret: signed in the clear, stored sealed.
	settings := []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", Startup: protocol.StartupDisabled, State: protocol.StateStopped},
		{Kind: protocol.KindWiFi, SSID: "Office", Security: "wpa2_personal", Passphrase: "correct horse battery"},
	}
	profile := map[string]any{"name": "Baseline", "settings": settings}
	if code, _ := admin.do(http.MethodPost, "/profiles", profile); code != http.StatusBadRequest {
		t.Fatalf("unsigned profile: %d", code)
	}
	profSig := opsign.Sign(ops, protocol.ProfileManifest(settings))
	profile["signature"] = profSig
	code, body = admin.do(http.MethodPost, "/profiles", profile)
	if code != http.StatusCreated {
		t.Fatalf("signed profile: %d %s", code, body)
	}
	got = decodeJSON[created](t, body)
	assign("profile", got.ID)

	// The editor sends a secret back blank, meaning "keep it"; with no new
	// signature, a rename keeps the old one.
	blank := []protocol.Setting{settings[0], settings[1]}
	blank[1].Passphrase = ""
	code, body = admin.do(http.MethodPost, "/profiles/"+got.ID, map[string]any{"name": "Baseline v2", "settings": blank})
	if code != http.StatusOK {
		t.Fatalf("rename profile: %d %s", code, body)
	}
	if r := decodeJSON[created](t, body); r.CurrentVersion != 1 || !r.Signed {
		t.Fatalf("a rename should keep version 1 and its signature: %s", body)
	}

	code, body = send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/profiles/"+got.ID+"/versions/1", nil)
	if code != http.StatusOK {
		t.Fatalf("agent fetch profile: %d %s", code, body)
	}
	pv := decodeJSON[protocol.ProfileVersionResponse](t, body)
	if err := opsign.Verify(trusted, protocol.ProfileManifest(pv.Settings), pv.Signature); err != nil {
		t.Fatalf("the agent can't verify what it was sent: %v", err)
	}

	// A changed passphrase under the old signature is refused, and so is
	// any change made without one.
	changed := []protocol.Setting{settings[0], settings[1]}
	changed[1].Passphrase = "an attacker's network"
	if code, _ := admin.do(http.MethodPost, "/profiles/"+got.ID, map[string]any{
		"name": "Baseline", "settings": changed, "signature": profSig,
	}); code != http.StatusBadRequest {
		t.Fatalf("re-keyed profile: %d", code)
	}
	if code, _ := admin.do(http.MethodPost, "/profiles/"+got.ID, map[string]any{
		"name": "Baseline", "settings": []protocol.Setting{settings[1]},
	}); code != http.StatusBadRequest {
		t.Fatalf("an unsigned change: %d", code)
	}
}

// Without OPERATIONS_KEYS, unsigned apps and profiles are accepted as before,
// and a signature given is still handed on to agents that require one.
func TestAppAndProfileSignaturesPassThroughWithoutServerKeys(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	ops, _ := release.GenerateKey()

	if code, _ := admin.do(http.MethodPost, "/apps", map[string]any{"name": "Plain", "package_id": "Plain.App"}); code != http.StatusCreated {
		t.Fatalf("unsigned app: %d", code)
	}
	sig := opsign.Sign(ops, protocol.AppDefinition{PackageID: "Signed.App"}.Manifest())
	code, body := admin.do(http.MethodPost, "/apps", map[string]any{"name": "Signed", "package_id": "Signed.App", "signature": sig})
	if code != http.StatusCreated || !decodeJSON[struct {
		Signed bool `json:"signed"`
	}](t, body).Signed {
		t.Fatalf("signed app: %d %s", code, body)
	}
	settings := []protocol.Setting{{Kind: protocol.KindService, Name: "Spooler", Startup: protocol.StartupDisabled}}
	if code, _ := admin.do(http.MethodPost, "/profiles", map[string]any{"name": "Plain", "settings": settings}); code != http.StatusCreated {
		t.Fatalf("unsigned profile: %d", code)
	}
}
