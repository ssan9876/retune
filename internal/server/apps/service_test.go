package apps_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/apps"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(st *store.Store) *apps.Service { return &apps.Service{Store: st} }

// newDevice creates a device directly through the store, mirroring the
// helper in store_m2_test.go: storetest exposes only DatabaseURL and New, and
// this package cannot reach store_test's own helpers.
func newDevice(t *testing.T, st *store.Store, hostname string) uuid.UUID {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: "SN1", SMBIOSUUID: "U1",
		Status: store.DeviceActive, CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d.ID
}

// Renaming an app does not make every device install it again; changing what
// gets installed does.
func TestUpdateBumpsTheVersionOnlyWhenTheDefinitionChanges(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	a, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if a.CurrentVersion != 1 {
		t.Fatalf("a new app starts at version 1, got %d", a.CurrentVersion)
	}

	renamed, err := svc.Update(ctx, a.ID, apps.NewApp{
		Name: "7-Zip archiver", Description: "handy", PackageID: "7zip.7zip", Actor: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.CurrentVersion != 1 {
		t.Errorf("renaming should not redeploy, got version %d", renamed.CurrentVersion)
	}

	pinned, err := svc.Update(ctx, a.ID, apps.NewApp{
		Name: "7-Zip archiver", PackageID: "7zip.7zip", PinnedVersion: "26.03", Actor: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pinned.CurrentVersion != 2 {
		t.Errorf("pinning a version is a new definition, got version %d", pinned.CurrentVersion)
	}
	v, err := svc.Version(ctx, a.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if v.PinnedVersion != "26.03" {
		t.Errorf("version 2 should carry the pin, got %+v", v)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	cases := map[string]apps.NewApp{
		"no name":         {PackageID: "7zip.7zip", Actor: "ops"},
		"no package":      {Name: "Nameless", Actor: "ops"},
		"a user scope":    {Name: "Per user", PackageID: "7zip.7zip", Scope: "user", Actor: "ops"},
		"a made-up scope": {Name: "Odd", PackageID: "7zip.7zip", Scope: "galaxy", Actor: "ops"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Create(ctx, in); !errors.Is(err, apps.ErrBadRequest) {
				t.Fatalf("want ErrBadRequest, got %v", err)
			}
		})
	}
}

// The reported install and the device's status are written together, so the
// console's summary can never disagree with the history behind it.
func TestRecordInstallWritesHistoryAndStatus(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	device := newDevice(t, st, "DESKTOP-APPS")

	a, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.RecordInstall(ctx, device, a.ID, protocol.AppResult{
		Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultSucceeded,
		InstalledVersion: "26.03",
	})
	if err != nil {
		t.Fatal(err)
	}

	rollup, err := st.Q().ItemStatusRollup(ctx, protocol.ItemKindApp, a.ID, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("want one succeeded, got %v", rollup)
	}
	rows, _, err := st.Q().ListAppInstalls(ctx, a.ID, nil, store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].InstalledVersion != "26.03" {
		t.Fatalf("the install should be in the history, got %+v", rows)
	}
}

// A failure with no detail of its own gets one that names the package, so an
// administrator can tell two failing apps apart from the rollup alone; a
// timeout additionally says the install may still be running (spec §8 rows
// 2-3).
func TestRecordInstallNamesThePackageInAFailureDetail(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	device := newDevice(t, st, "DESKTOP-FAIL")

	a, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RecordInstall(ctx, device, a.ID, protocol.AppResult{
		Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultFailed, ExitCode: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordInstall(ctx, device, a.ID, protocol.AppResult{
		Version: 1, Intent: protocol.IntentInstall, Status: protocol.ResultFailed, ExitCode: -1,
		Error: "timed out after 15m0s",
	}); err != nil {
		t.Fatal(err)
	}

	rows, _, err := st.Q().ListAppInstalls(ctx, a.ID, nil, store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 installs, got %d", len(rows))
	}
	// ListAppInstalls orders newest first, so rows[1] is the plain failure and
	// rows[0] is the timeout.
	if !strings.Contains(rows[1].Detail, "7zip.7zip") {
		t.Errorf("a plain failure's detail should name the package, got %q", rows[1].Detail)
	}
	if !strings.Contains(rows[0].Detail, "7zip.7zip") || !strings.Contains(rows[0].Detail, "may still be running") {
		t.Errorf("a timeout's detail should name the package and say it may still be running, got %q", rows[0].Detail)
	}
}

// Deleting an app takes its assignments with it, or a device would keep being
// told to install something that no longer exists.
func TestDeleteRemovesAssignments(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	a, err := svc.Create(ctx, apps.NewApp{Name: "Doomed", PackageID: "x.y", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindApp, ItemID: a.ID,
		GroupID:   store.BuiltinGroupID,
		Mode:      store.ModeInclude,
		CreatedAt: time.Now(),
		CreatedBy: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, a.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Q().ListAssignments(ctx, protocol.ItemKindApp, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("assignments should have gone too, got %+v", rows)
	}
}
