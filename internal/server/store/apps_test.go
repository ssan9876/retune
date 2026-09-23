package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestAppRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "7-Zip", Description: "archiver",
		CurrentVersion: 1, CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 1, PackageID: "7zip.7zip", Scope: "machine",
		Hash: "abc", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetApp(ctx, store.DefaultTenantID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "7-Zip" || got.CurrentVersion != 1 {
		t.Fatalf("app = %+v", got)
	}

	v, err := q.GetAppVersion(ctx, store.DefaultTenantID, a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v.PackageID != "7zip.7zip" || v.Scope != "machine" {
		t.Fatalf("version = %+v", v)
	}

	// A name is unique per tenant, case-insensitively, so two people cannot
	// each create "7-zip" and wonder which one is assigned.
	dup := a
	dup.ID, dup.Name = uuid.Must(uuid.NewV7()), "7-zip"
	if err := q.CreateApp(ctx, dup); err == nil {
		t.Error("a duplicate name should be refused")
	}

	if _, err := q.GetApp(ctx, store.DefaultTenantID, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing app should be ErrNotFound, got %v", err)
	}
}

func TestAppQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "Scoped App", CurrentVersion: 1,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 1, PackageID: "7zip.7zip", Scope: "machine",
		Hash: "abc", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetApp(ctx, other, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if _, err := q.GetAppVersion(ctx, other, a.ID, 1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the version: %v", err)
	}
	changed := a
	changed.Name = "Hacked"
	if err := q.UpdateApp(ctx, other, changed); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteApp(ctx, other, a.ID); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetApp(ctx, store.DefaultTenantID, a.ID)
	if err != nil || got.Name != "Scoped App" {
		t.Errorf("another tenant must not change or delete the row: %+v %v", got, err)
	}
}

// TestAppVersionsAreImmutable mirrors the scripts test: a later version must
// not change what an earlier install asked for.
func TestAppVersionsAreImmutable(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "Notepad++", CurrentVersion: 2,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 1, PackageID: "Notepad++.Notepad++", PinnedVersion: "8.6",
		Scope: "machine", Hash: "h1", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 2, PackageID: "Notepad++.Notepad++", PinnedVersion: "8.7",
		Scope: "machine", Hash: "h2", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}

	v1, err := q.GetAppVersion(ctx, store.DefaultTenantID, a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v1.PinnedVersion != "8.6" {
		t.Fatalf("version 1 pinned = %q, a later version must not change it", v1.PinnedVersion)
	}

	versions, err := q.ListAppVersions(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != 2 {
		t.Fatalf("want newest first, got %+v", versions)
	}

	if _, err := q.GetAppVersion(ctx, store.DefaultTenantID, a.ID, 9); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for a missing version, got %v", err)
	}
}

// TestAppInstallsSurviveDeletion is the same rule as scripts: installs
// outlive the app they describe, because what happened on a machine stays
// true after somebody deletes the deployment.
func TestAppInstallsSurviveDeletion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	device := newDevice(t, q, "DESKTOP-APPS")
	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "Doomed", CurrentVersion: 1,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAppVersion(ctx, store.AppVersion{
		AppID: a.ID, Version: 1, PackageID: "doomed.doomed", Scope: "machine",
		Hash: "h", CreatedAt: now, CreatedBy: "ops",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertAppInstall(ctx, store.AppInstall{
		ID: uuid.Must(uuid.NewV7()), AppID: a.ID, Version: 1, DeviceID: device.ID,
		Intent: "install", Status: "succeeded", InstalledVersion: "26.03",
		StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteApp(ctx, store.DefaultTenantID, a.ID); err != nil {
		t.Fatal(err)
	}
	rows, total, err := q.ListAppInstalls(ctx, a.ID, nil, store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].InstalledVersion != "26.03" {
		t.Fatalf("the install should have survived, got %d rows %+v", total, rows)
	}
	if rows[0].Hostname != "DESKTOP-APPS" {
		t.Fatalf("the install should carry the device hostname, got %+v", rows[0])
	}

	// The version is deleted with the app.
	if _, err := q.GetAppVersion(ctx, store.DefaultTenantID, a.ID, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("versions should be deleted with the app, got %v", err)
	}
}

// TestListAppInstallsFiltersByDevice mirrors ListScriptRuns's device filter.
func TestListAppInstallsFiltersByDevice(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	a := store.App{
		ID: uuid.Must(uuid.NewV7()), Name: "Fleet wide", CurrentVersion: 1,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	dA := newDevice(t, q, "A")
	dB := newDevice(t, q, "B")

	for _, d := range []uuid.UUID{dA.ID, dB.ID} {
		if err := q.InsertAppInstall(ctx, store.AppInstall{
			ID: uuid.Must(uuid.NewV7()), AppID: a.ID, Version: 1, DeviceID: d,
			Intent: "install", Status: "succeeded",
			StartedAt: now, FinishedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, total, err := q.ListAppInstalls(ctx, a.ID, nil, store.Page{}, store.Unscoped); err != nil || total != 2 {
		t.Fatalf("unfiltered: total %d err %v", total, err)
	}
	rows, total, err := q.ListAppInstalls(ctx, a.ID, &dB.ID, store.Page{}, store.Unscoped)
	if err != nil || total != 1 || rows[0].Hostname != "B" {
		t.Fatalf("filtered by device: total %d rows %+v err %v", total, rows, err)
	}
}
