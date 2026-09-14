// Package e2e exercises server and agent together.
package e2e

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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
	"retune/internal/server/app"
	"retune/internal/server/apps"
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
	d1, _ := a.Store.Q().GetDevice(ctx, uuid.MustParse(id1.DeviceID))
	if d1.LastSeenAt == nil || d1.AgentVersion != "e2e" || d1.Hostname != "PC-001" {
		t.Fatalf("device after checkin: %+v", d1)
	}

	// Reimage: same hardware enrolls again; old identity is rejected.
	id2, err := enrollment.Enroll(ctx, opts())
	if err != nil {
		t.Fatal(err)
	}
	if d1, _ = a.Store.Q().GetDevice(ctx, uuid.MustParse(id1.DeviceID)); d1.Status != store.DeviceReplaced {
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
	if err := a.Store.Q().SetDeviceStatus(ctx, uuid.MustParse(id2.DeviceID), store.DeviceRetired); err != nil {
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
	if err := a.Store.Q().DeleteAssignment(ctx, installAssignment); err != nil {
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
