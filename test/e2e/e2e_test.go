// Package e2e exercises server and agent together.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/identity"
	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/adminapi"
	"retune/internal/server/app"
	"retune/internal/server/apps"
	"retune/internal/server/auth"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestEnrollAndCheckin(t *testing.T) {
	ctx := context.Background()
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 2 * time.Minute,
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	defer srv.Close()

	maxUses := 2
	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "e2e", MaxUses: &maxUses, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pin := pki.Fingerprint(a.CA.Cert().Raw)
	facts := protocol.DeviceFacts{Hostname: "PC-001", Serial: "SN1", SMBIOSUUID: "UUID-1", OSVersion: "Windows 11 Pro"}
	opts := func() enrollment.Options {
		return enrollment.Options{ServerURL: srv.URL, Token: token, Pin: pin, Facts: facts,
			Store: identity.Store{Dir: t.TempDir(), Keys: identity.PlainKeys{}}}
	}

	// A wrong pin fails before the token is used.
	bad := opts()
	bad.Pin = "sha256:0000"
	if _, err := enrollment.Enroll(ctx, bad); err == nil {
		t.Fatal("enrollment with wrong pin must fail")
	}

	// Enroll, reload identity from disk, check in.
	o1 := opts()
	id1, err := enrollment.Enroll(ctx, o1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.Enroll(ctx, o1); !errors.Is(err, enrollment.ErrAlreadyEnrolled) {
		t.Fatalf("second enroll into same dir: %v", err)
	}
	loaded, err := o1.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := enrollment.Connect(loaded)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c1.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || resp.IntervalSeconds != 120 {
		t.Fatalf("checkin: %+v, %v", resp, err)
	}
	d1, _ := a.Store.Q().GetDevice(ctx, store.DefaultTenantID, uuid.MustParse(id1.DeviceID))
	if d1.LastSeenAt == nil || d1.AgentVersion != "e2e" || d1.Hostname != "PC-001" {
		t.Fatalf("device after checkin: %+v", d1)
	}

	// Reimage: same hardware enrolls again; old identity is rejected.
	id2, err := enrollment.Enroll(ctx, opts())
	if err != nil {
		t.Fatal(err)
	}
	if d1, _ = a.Store.Q().GetDevice(ctx, store.DefaultTenantID, uuid.MustParse(id1.DeviceID)); d1.Status != store.DeviceReplaced {
		t.Fatalf("old device status = %s", d1.Status)
	}
	var he *client.HTTPError
	if _, err := c1.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("replaced device checkin err = %v", err)
	}

	// Token had 2 uses; a third enrollment is refused.
	if _, err := enrollment.Enroll(ctx, opts()); !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("exhausted token err = %v", err)
	}

	// Retired device is rejected.
	c2, err := enrollment.Connect(id2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatalf("new device checkin: %v", err)
	}
	if err := a.Store.Q().SetDeviceStatus(ctx, store.DefaultTenantID, uuid.MustParse(id2.DeviceID), store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("retired device checkin err = %v", err)
	}
}

// TestAppDeploymentEndToEnd proves the whole application path: an app created
// and assigned to a group reaches an enrolled agent at check-in, the agent
// fetches its definition and reports a result, the console's rollup and
// per-device detail settle to match, and reassigning with uninstall intent
// and reporting that leaves the device succeeded with a detail that says the
// software went away.
func TestAppDeploymentEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 2 * time.Minute,
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Enroll one device, exactly as above: a token, then enrollment.Enroll and
	// enrollment.Connect for a client that carries the device's own
	// certificate.
	maxUses := 1
	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "apps-e2e", MaxUses: &maxUses, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pin := pki.Fingerprint(a.CA.Cert().Raw)
	facts := protocol.DeviceFacts{Hostname: "PC-APPS", Serial: "SN-APPS", SMBIOSUUID: "UUID-APPS", OSVersion: "Windows 11 Pro"}
	id, err := enrollment.Enroll(ctx, enrollment.Options{
		ServerURL: srv.URL, Token: token, Pin: pin, Facts: facts,
		Store: identity.Store{Dir: t.TempDir(), Keys: identity.PlainKeys{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := enrollment.Connect(id)
	if err != nil {
		t.Fatal(err)
	}

	// Create the app and assign it to All devices, the builtin group every
	// device joins at enrollment. No options are given, so it defaults to an
	// install.
	created, err := a.Apps.Create(ctx, apps.NewApp{
		Name: "7-Zip", Description: "archiver", PackageID: "7zip.7zip", Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	installAssignment := uuid.Must(uuid.NewV7())
	if _, err := a.Store.Q().CreateAssignment(ctx, store.Assignment{
		ID: installAssignment, ItemKind: protocol.ItemKindApp, ItemID: created.ID,
		GroupID: store.BuiltinGroupID, Mode: store.ModeInclude,
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// The app reaches the agent at its current version.
	checkinResp, err := agent.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	items := checkinResp.Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindApp || items[0].Version != 1 {
		t.Fatalf("the app should be offered once, at version 1, got %+v", items)
	}

	// The agent can read the definition it was offered, and only that one.
	versionBody, err := agent.FetchApp(ctx, created.ID.String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	version := versionBody
	if version.PackageID != "7zip.7zip" || version.Scope != "machine" {
		t.Fatalf("definition = %+v", version)
	}

	// The agent reports success, as if winget had just installed it.
	now := time.Now().UTC()
	if err := agent.ReportAppResult(ctx, created.ID.String(), protocol.AppResult{
		Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultSucceeded,
		InstalledVersion: "26.03", StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// What it reports settles the console's view of that device.
	rollup, err := a.Store.Q().ItemStatusRollup(ctx, protocol.ItemKindApp, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}
	statuses, _, err := a.Store.Q().ListItemStatus(ctx, protocol.ItemKindApp, created.ID, "", store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("want one device status, got %+v", statuses)
	}
	detail := statuses[0].Detail
	if !strings.Contains(detail, "26.03") {
		t.Errorf("the detail should name the version that landed, got %q", detail)
	}

	// Uninstall intent is a different instruction, not the absence of one.
	// Re-assigning with intent uninstall and reporting that result leaves the
	// device succeeded, with a detail that says it was removed. The old
	// include assignment has to go first: the unique index on
	// (item_kind, item_id, group_id, mode) would otherwise collide with it.
	if err := a.Store.Q().DeleteAssignment(ctx, store.DefaultTenantID, installAssignment); err != nil {
		t.Fatal(err)
	}
	uninstallOptions, err := protocol.AppOptions{Intent: protocol.IntentUninstall, TimeoutSeconds: 900}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindApp, ItemID: created.ID,
		GroupID: store.BuiltinGroupID, Mode: store.ModeInclude, Options: uninstallOptions,
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}

	checkinResp, err = agent.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	if len(checkinResp.Items) != 1 || checkinResp.Items[0].Kind != protocol.ItemKindApp {
		t.Fatalf("the app should still be offered, got %+v", checkinResp.Items)
	}
	offered, err := protocol.ParseAppOptions(checkinResp.Items[0].Options)
	if err != nil {
		t.Fatal(err)
	}
	if offered.Intent != protocol.IntentUninstall {
		t.Fatalf("the reassignment should carry uninstall intent, got %+v", offered)
	}

	now = time.Now().UTC()
	if err := agent.ReportAppResult(ctx, created.ID.String(), protocol.AppResult{
		Version: 1, Intent: protocol.IntentUninstall, Status: protocol.ResultSucceeded,
		StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rollup, err = a.Store.Q().ItemStatusRollup(ctx, protocol.ItemKindApp, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded after removal, got %v", rollup)
	}
	statuses, _, err = a.Store.Q().ListItemStatus(ctx, protocol.ItemKindApp, created.ID, "", store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 {
		t.Fatalf("want one device status after removal, got %+v", statuses)
	}
	afterRemoval := statuses[0].Detail
	if !strings.Contains(afterRemoval, "removed") {
		t.Errorf("the detail should say it went, got %q", afterRemoval)
	}
}

// TestAgentSelfUpdateEndToEnd proves the whole agent self-update path: an
// administrator uploads a build and assigns it to a group, an enrolled device
// in that group is offered it at check-in, fetches its definition, and
// downloads bytes that hash to what the definition promised; a second device
// that was never assigned the build cannot download it; and a result the
// device reports settles the console's rollup.
func TestAgentSelfUpdateEndToEnd(t *testing.T) {
	ctx := context.Background()
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 2 * time.Minute,
		SessionTTL:       12 * time.Hour,
		AgentReleaseKeys: []release.PublicKey{priv.Public()},
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	defer srv.Close()

	// An administrator signs in exactly as the console would: a session
	// cookie plus the CSRF token it returns, kept across requests by a jar.
	if _, err := a.Auth.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	adminHTTP := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.CA.Pool()}},
	}
	status, body := send(t, adminHTTP, http.MethodPost, srv.URL+"/api/admin/v1/session", map[string]string{
		"email": "ops@example.com", "password": "correct horse battery", "totp_code": "",
	})
	if status != http.StatusOK {
		t.Fatalf("admin login: %d %s", status, body)
	}
	var loginResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(body, &loginResp); err != nil {
		t.Fatal(err)
	}

	// The build is uploaded as a raw body, not JSON: the version and notes
	// travel as query parameters instead.
	const buildBytes = "a pretend agent binary 1.2.3, self-update end to end"
	// The signature is what admits a build: the server refuses anything the
	// release key did not sign.
	buildSum := sha256.Sum256([]byte(buildBytes))
	sig := release.Sign(priv, release.Manifest{Version: "1.2.3", SHA256: hex.EncodeToString(buildSum[:])})
	sigJSON, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	sigHeader := base64.StdEncoding.EncodeToString(sigJSON)
	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/api/admin/v1/agent-versions?version=1.2.3&notes=e2e", strings.NewReader(buildBytes))
	if err != nil {
		t.Fatal(err)
	}
	uploadReq.Header.Set("Content-Type", "application/octet-stream")
	uploadReq.Header.Set(adminapi.CSRFHeader, loginResp.CSRFToken)
	uploadReq.Header.Set(adminapi.SignatureHeader, sigHeader)
	uploadRes, err := adminHTTP.Do(uploadReq)
	if err != nil {
		t.Fatal(err)
	}
	defer uploadRes.Body.Close()
	uploadBody, err := io.ReadAll(uploadRes.Body)
	if err != nil {
		t.Fatal(err)
	}
	if uploadRes.StatusCode != http.StatusCreated {
		t.Fatalf("upload agent version: %d %s", uploadRes.StatusCode, uploadBody)
	}
	uploaded := decodeJSON[struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}](t, uploadBody)
	versionID := uuid.MustParse(uploaded.ID)

	// Two devices enroll on the same token. Only one of them will end up
	// assigned the build.
	maxUses := 2
	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{
		Label: "self-update-e2e", MaxUses: &maxUses, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := pki.Fingerprint(a.CA.Cert().Raw)
	enrollWithRawClient := func(hostname, serial string) (uuid.UUID, *http.Client) {
		t.Helper()
		facts := protocol.DeviceFacts{Hostname: hostname, Serial: serial, SMBIOSUUID: "UUID-" + serial, OSVersion: "Windows 11 Pro"}
		id, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: srv.URL, Token: token, Pin: pin, Facts: facts,
			Store: identity.Store{Dir: t.TempDir(), Keys: identity.PlainKeys{}},
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, err := id.TLSCertificate()
		if err != nil {
			t.Fatal(err)
		}
		return uuid.MustParse(id.DeviceID), &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: a.CA.Pool(), Certificates: []tls.Certificate{cert},
			}},
		}
	}
	deviceID, device := enrollWithRawClient("PC-UPDATING", "SN-UPDATING")
	_, other := enrollWithRawClient("PC-UNASSIGNED", "SN-UNASSIGNED")

	// Every enrolled device already belongs to the builtin "All devices"
	// group, so keeping the second device unassigned needs a group of its
	// own with only the first device as a member.
	pilot := store.Group{
		ID: uuid.Must(uuid.NewV7()), Name: "Pilot", Kind: store.GroupStatic,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := a.Store.Q().CreateGroup(ctx, pilot); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.Q().AddGroupMember(ctx, pilot.ID, deviceID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: versionID,
		GroupID: pilot.ID, Mode: store.ModeInclude,
		CreatedAt: time.Now().UTC(), CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// The assigned device checks in and is offered the build.
	status, body = send(t, device, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	// The build reaches the agent.
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindAgent {
		t.Fatalf("the build should be offered once, got %+v", items)
	}

	// It fetches the definition, then the bytes.
	defURL := srv.URL + "/api/agent/v1/agent-versions/" + versionID.String()
	binaryURL := defURL + "/binary"
	status, defBody := send(t, device, http.MethodGet, defURL, nil)
	if status != http.StatusOK {
		t.Fatalf("definition: %d %s", status, defBody)
	}
	status, binaryBody := send(t, device, http.MethodGet, binaryURL, nil)
	if status != http.StatusOK {
		t.Fatalf("binary: %d", status)
	}

	// The definition promises a hash, and the bytes honour it.
	def := decodeJSON[protocol.AgentVersionResponse](t, defBody)
	sum := sha256.Sum256(binaryBody)
	if hex.EncodeToString(sum[:]) != def.SHA256 {
		t.Fatalf("the downloaded bytes do not match the promised hash")
	}
	if def.SizeBytes != int64(len(binaryBody)) {
		t.Errorf("size = %d, downloaded %d", def.SizeBytes, len(binaryBody))
	}

	// The definition also carries what the agent needs to verify the build
	// against the release key it trusts, without a separate round trip.
	if def.KeyID != priv.Public().ID() {
		t.Errorf("key_id = %q, want %q", def.KeyID, priv.Public().ID())
	}
	rawSig, err := base64.StdEncoding.DecodeString(def.Signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	gotSig := release.Signature{Version: def.Version, SHA256: def.SHA256, KeyID: def.KeyID, Signature: rawSig}
	if err := release.Verify([]release.PublicKey{priv.Public()}, release.Manifest{Version: def.Version, SHA256: def.SHA256}, gotSig); err != nil {
		t.Errorf("verify definition signature: %v", err)
	}

	// A device that was never assigned the build cannot fetch it.
	if status, _ := send(t, other, http.MethodGet, binaryURL, nil); status != http.StatusNotFound {
		t.Errorf("an unassigned device must not download a build, got %d", status)
	}

	// The device reports how the update went, as if it had swapped itself in
	// and checked in cleanly on the new build.
	status, body = send(t, device, http.MethodPost, defURL+"/result", protocol.AgentUpdateResult{
		Version: "1.2.3", Status: protocol.ResultSucceeded, Detail: "updated cleanly", ReportedAt: time.Now().UTC(),
	})
	if status != http.StatusNoContent {
		t.Fatalf("report result: %d %s", status, body)
	}

	// What it reports settles the console's rollup.
	rollup, err := a.Store.Q().ItemStatusRollup(ctx, protocol.ItemKindAgent, versionID)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}

	// A later check-in reporting the assigned version is itself proof of
	// success, with no separate result report required.
	status, body = send(t, device, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.2.3"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	rollup, err = a.Store.Q().ItemStatusRollup(ctx, protocol.ItemKindAgent, versionID)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}
}

// send performs a JSON request and returns the status and raw body.
func send(t *testing.T, c *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func decodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}
