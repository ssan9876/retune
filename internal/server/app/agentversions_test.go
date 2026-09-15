package app_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/adminapi"
	"retune/internal/server/store"
)

type agentVersionResp struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Notes     string `json:"notes"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// signatureHeader builds the X-Retune-Signature value for body under priv.
func signatureHeader(t *testing.T, priv release.PrivateKey, version, body string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	sig := release.Sign(priv, release.Manifest{Version: version, SHA256: hex.EncodeToString(sum[:])})
	b, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// uploadAgentVersion posts a build body signed with the test release key.
func uploadAgentVersion(t *testing.T, admin *adminClient, version, body string) (int, []byte) {
	t.Helper()
	return admin.doRawWithHeaders(http.MethodPost,
		"/agent-versions?version="+version+"&notes=test", "application/octet-stream",
		map[string]string{adminapi.SignatureHeader: signatureHeader(t, testReleaseKey, version, body)},
		bytes.NewReader([]byte(body)))
}

func TestAgentVersionLifecycle(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := uploadAgentVersion(t, admin, "1.2.3", "a pretend agent binary stamped 1.2.3")
	if status != http.StatusCreated {
		t.Fatalf("upload: %d %s", status, body)
	}
	v := decodeJSON[agentVersionResp](t, body)
	if v.Version != "1.2.3" || v.SHA256 == "" || v.SizeBytes == 0 {
		t.Fatalf("version = %+v", v)
	}
	if v.KeyID != testReleaseKey.Public().ID() {
		t.Errorf("key_id = %q, want %q", v.KeyID, testReleaseKey.Public().ID())
	}
	if v.Signature == "" {
		t.Error("signature should not be empty")
	}

	status, body = admin.do(http.MethodGet, "/agent-versions", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	if !strings.Contains(string(body), "1.2.3") {
		t.Errorf("the listing should name the build, got %s", body)
	}

	// The same version twice is refused rather than silently replacing bytes.
	if status, _ := uploadAgentVersion(t, admin, "1.2.3", "different bytes"); status != http.StatusConflict {
		t.Errorf("a duplicate version should be 409, got %d", status)
	}

	status, body = admin.do(http.MethodDelete, "/agent-versions/"+v.ID, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
}

func TestUploadWithoutASignatureIsRefused(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	status, body := admin.doRaw(http.MethodPost, "/agent-versions?version=1.0.0",
		"application/octet-stream", bytes.NewReader([]byte("b")))
	if status != http.StatusBadRequest || !strings.Contains(string(body), "X-Retune-Signature") {
		t.Fatalf("want 400 naming the header, got %d %s", status, body)
	}
	status, body = admin.doRawWithHeaders(http.MethodPost, "/agent-versions?version=1.0.0",
		"application/octet-stream", map[string]string{adminapi.SignatureHeader: "!!not base64"}, bytes.NewReader([]byte("b")))
	if status != http.StatusBadRequest {
		t.Fatalf("garbage header: want 400, got %d %s", status, body)
	}

	// Both refusals above are exactly the kind of probe -- an admin account
	// posting to /agent-versions with no valid signature -- this milestone
	// exists to make visible, so each one must leave a trace in the audit
	// log, not just a 400 to the caller who sent it.
	status, body = admin.do(http.MethodGet, "/audit", nil)
	if status != http.StatusOK {
		t.Fatalf("audit: %d %s", status, body)
	}
	var listing struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, e := range listing.Items {
		if e.Action == "agent_version.rejected" {
			rejected++
		}
	}
	if rejected != 2 {
		t.Errorf("want 2 agent_version.rejected audit entries, got %d (%s)", rejected, body)
	}
}

func TestUploadWithAnUnknownKeyIsRefused(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	other, _ := release.GenerateKey()
	status, body := admin.doRawWithHeaders(http.MethodPost, "/agent-versions?version=1.0.0",
		"application/octet-stream",
		map[string]string{adminapi.SignatureHeader: signatureHeader(t, other, "1.0.0", "b")},
		bytes.NewReader([]byte("b")))
	if status != http.StatusBadRequest || !strings.Contains(string(body), "not a configured release key") {
		t.Fatalf("want 400, got %d %s", status, body)
	}
}

// A read-only administrator can look but not upload.
func TestAgentVersionsAreClosedToReadOnlyAdmins(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/agent-versions", nil); status != http.StatusOK {
		t.Error("a read-only admin should be able to list builds")
	}
	if status, _ := uploadAgentVersion(t, c, "9.9.9", "x"); status != http.StatusForbidden {
		t.Errorf("a read-only admin must not upload, got %d", status)
	}
}

// An agent assignment carries a rollback deadline, validated at the API.
func TestAgentAssignmentDeadline(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	_, body := uploadAgentVersion(t, admin, "1.2.3", "bytes stamped 1.2.3")
	v := decodeJSON[agentVersionResp](t, body)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"deadline_seconds": 120},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"deadline_seconds":120`) {
		t.Errorf("the stored options should keep the deadline, got %s", body)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"deadline_seconds": 5},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("a deadline below the floor should be refused, got %d %s", status, body)
	}
}

// A device may only download a build it has been assigned. An unassigned one
// is a 404 -- the same answer as one that does not exist, which is all an
// agent needs to know.
func TestAgentDownloadsOnlyAssignedBuilds(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	const payload = "a pretend agent binary stamped 1.2.3"
	_, body := uploadAgentVersion(t, admin, "1.2.3", payload)
	v := decodeJSON[agentVersionResp](t, body)

	for _, path := range []string{"", "/binary"} {
		url := srv.URL + "/api/agent/v1/agent-versions/" + v.ID + path
		if status, _ := send(t, agent, http.MethodGet, url, nil); status != http.StatusNotFound {
			t.Fatalf("an unassigned build must not be readable at %q, got %d", path, status)
		}
	}

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	// The definition says what to expect before a byte is downloaded.
	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("definition: %d %s", status, body)
	}
	def := decodeJSON[protocol.AgentVersionResponse](t, body)
	if def.Version != "1.2.3" || def.SHA256 != v.SHA256 || def.SizeBytes != int64(len(payload)) {
		t.Fatalf("definition = %+v", def)
	}

	// And the bytes are exactly what was uploaded.
	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID+"/binary", nil)
	if status != http.StatusOK {
		t.Fatalf("binary: %d", status)
	}
	if string(body) != payload {
		t.Errorf("downloaded %q, want %q", body, payload)
	}
}

// A reported outcome reaches the console's rollup, and a rollback says which
// build failed rather than going quiet.
func TestAgentUpdateResultIsRecorded(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	_, body := uploadAgentVersion(t, admin, "2.0.0", "bytes stamped 2.0.0")
	v := decodeJSON[agentVersionResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID+"/result",
		protocol.AgentUpdateResult{
			Version: "2.0.0", Status: protocol.ResultFailed,
			RolledBackFrom: "2.0.0", Detail: "the new agent never checked in",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/agent/"+v.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemFailed] != 1 {
		t.Fatalf("want one failed, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "never checked in") {
		t.Errorf("the detail should say what happened, got %q", resp.Items[0].Detail)
	}
}

// Check-in offers an assigned build.
func TestAgentBuildReachesTheAgent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	_, body := uploadAgentVersion(t, admin, "1.2.3", "bytes stamped 1.2.3")
	v := decodeJSON[agentVersionResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindAgent {
		t.Fatalf("the build should be offered, got %+v", items)
	}
}

// A device that checks in already running the version it was assigned is
// treated as having succeeded, whether it got there by self-update or by an
// MSI that already carried that version -- there is no other way to tell.
func TestADeviceRunningTheAssignedBuildIsRecordedAsSucceeded(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-ALREADY-CURRENT")

	_, body := uploadAgentVersion(t, admin, "9.0.0", "bytes stamped 9.0.0")
	v := decodeJSON[agentVersionResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "9.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/agent/"+v.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", resp.Rollup)
	}

	// A second check-in reporting the same version leaves the rollup as is.
	status, body = send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "9.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	status, body = admin.do(http.MethodGet, "/items/agent/"+v.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp = decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want still one succeeded, got %v", resp.Rollup)
	}
}
