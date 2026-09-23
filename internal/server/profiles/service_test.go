package profiles_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/profiles"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(st *store.Store) *profiles.Service {
	return &profiles.Service{Store: st, Now: time.Now}
}

func device(t *testing.T, st *store.Store, hostname string) store.Device {
	t.Helper()
	now := time.Now()
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: store.DeviceActive,
		CertSerial: hostname, CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func settings() []protocol.Setting {
	return []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateStopped},
		{Kind: protocol.KindFile, Path: "C:/temp/a.txt", ContentBase64: "aGk="},
	}
}

func TestCreateStoresFirstVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Baseline", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if p.CurrentVersion != 1 {
		t.Fatalf("version = %d, want 1", p.CurrentVersion)
	}
	_, got, err := svc.Version(ctx, p.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "Spooler" {
		t.Fatalf("settings = %+v", got)
	}
}

// Settings keep the order they were written in: an author who writes a file and
// then starts a service that reads it expects that order.
func TestSettingOrderIsPreserved(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	in := []protocol.Setting{
		{Kind: protocol.KindFile, Path: "C:/temp/z.txt", ContentBase64: "aGk="},
		{Kind: protocol.KindService, Name: "Alpha", State: protocol.StateRunning},
		{Kind: protocol.KindFile, Path: "C:/temp/a.txt", ContentBase64: "aGk="},
	}
	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Ordered", Settings: in, Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := svc.Version(ctx, p.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range in {
		if got[i].Identity() != in[i].Identity() {
			t.Fatalf("setting %d = %s, want %s", i, got[i].Identity(), in[i].Identity())
		}
	}
}

func TestOnlySettingChangesMakeVersions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Baseline", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := svc.Update(ctx, p.ID, profiles.NewProfile{
		Name: "Renamed", Description: "same settings", Settings: settings(), Actor: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.CurrentVersion != 1 {
		t.Fatalf("renaming should not make a version, got %d", renamed.CurrentVersion)
	}

	changed := append(settings(), protocol.Setting{
		Kind: protocol.KindRegistry, Hive: "HKLM", Key: "SOFTWARE\\Retune",
		Name: "Managed", Type: protocol.RegDWord, Data: "1",
	})
	edited, err := svc.Update(ctx, p.ID, profiles.NewProfile{Name: "Renamed", Settings: changed, Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if edited.CurrentVersion != 2 {
		t.Fatalf("changed settings should make version 2, got %d", edited.CurrentVersion)
	}

	_, v1, err := svc.Version(ctx, p.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(v1) != 2 {
		t.Fatalf("version 1 should still have 2 settings, got %d", len(v1))
	}
}

func TestCreateRejectsBadSettings(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	_, err := svc.Create(ctx, profiles.NewProfile{
		Name: "Broken", Actor: "ops",
		Settings: []protocol.Setting{
			{Kind: protocol.KindRegistry, Hive: "HKXX", Key: "X", Name: "Y", Type: protocol.RegSZ},
		},
	})
	if !errors.Is(err, profiles.ErrBadRequest) {
		t.Fatalf("an unknown hive should be refused when the profile is saved, got %v", err)
	}

	if _, err := svc.Create(ctx, profiles.NewProfile{Name: "Empty", Actor: "ops"}); !errors.Is(err, profiles.ErrBadRequest) {
		t.Errorf("a profile with no settings should be refused, got %v", err)
	}
}

func TestRecordStatusRollsUp(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "RECONCILED")

	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Baseline", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}

	report := func(results ...protocol.SettingResult) {
		t.Helper()
		if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{Version: 1, Settings: results}); err != nil {
			t.Fatal(err)
		}
	}
	itemStatus := func() (string, string) {
		t.Helper()
		rows, _, err := st.Q().ListItemStatus(ctx, protocol.ItemKindProfile, p.ID, "", store.Page{}, store.Unscoped)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("want one item status, got %d", len(rows))
		}
		return rows[0].Status, rows[0].Detail
	}

	// Everything compliant or remediated rolls up to succeeded.
	report(
		protocol.SettingResult{Identity: "service:spooler", Status: protocol.SettingCompliant},
		protocol.SettingResult{Identity: "file:c:/temp/a.txt", Status: protocol.SettingRemediated},
	)
	if status, _ := itemStatus(); status != store.ItemSucceeded {
		t.Fatalf("status = %q, want succeeded", status)
	}

	// One error fails the profile and says which setting.
	report(
		protocol.SettingResult{Identity: "service:spooler", Status: protocol.SettingError, Detail: "access denied"},
		protocol.SettingResult{Identity: "file:c:/temp/a.txt", Status: protocol.SettingCompliant},
	)
	status, detail := itemStatus()
	if status != store.ItemFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	if detail != "service:spooler is failed" {
		t.Errorf("detail = %q, it should name the setting", detail)
	}

	// A conflict outranks a failure: it needs a decision, not a retry.
	report(
		protocol.SettingResult{Identity: "service:spooler", Status: protocol.SettingError},
		protocol.SettingResult{Identity: "file:c:/temp/a.txt", Status: protocol.SettingConflict},
	)
	if status, _ := itemStatus(); status != store.ItemConflict {
		t.Fatalf("status = %q, want conflict", status)
	}

	rollup, err := st.Q().SettingStatusRollup(ctx, p.ID, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.SettingError] != 1 || rollup[store.SettingConflict] != 1 {
		t.Fatalf("per-setting rollup = %v", rollup)
	}
}

// A setting dropped from a profile should stop showing its last result.
func TestRemovedSettingsStopBeingReported(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "TRIMMED")

	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Baseline", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{
		Version: 1,
		Settings: []protocol.SettingResult{
			{Identity: "service:spooler", Status: protocol.SettingCompliant},
			{Identity: "file:c:/temp/a.txt", Status: protocol.SettingCompliant},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{
		Version:  2,
		Settings: []protocol.SettingResult{{Identity: "service:spooler", Status: protocol.SettingCompliant}},
	}); err != nil {
		t.Fatal(err)
	}

	rows, total, err := st.Q().ListSettingStatus(ctx, p.ID, "", store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || rows[0].Identity != "service:spooler" {
		t.Fatalf("the dropped setting should be gone, got %+v", rows)
	}
}

func TestClearForDevice(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "UNASSIGNED")

	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Baseline", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{
		Version:  1,
		Settings: []protocol.SettingResult{{Identity: "service:spooler", Status: protocol.SettingCompliant}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ClearForDevice(ctx, d.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, total, err := st.Q().ListSettingStatus(ctx, p.ID, "", store.Page{}, store.Unscoped); err != nil || total != 0 {
		t.Fatalf("total %d err %v", total, err)
	}
}

func TestRecordStatusRejectsNonsense(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "BAD")
	p, err := svc.Create(ctx, profiles.NewProfile{Name: "Strict", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{Version: 1}); !errors.Is(err, profiles.ErrBadRequest) {
		t.Errorf("an empty report should be rejected, got %v", err)
	}
	if err := svc.RecordStatus(ctx, d.ID, p.ID, protocol.ProfileStatus{
		Version:  1,
		Settings: []protocol.SettingResult{{Identity: "x", Status: "vibes"}},
	}); !errors.Is(err, profiles.ErrBadRequest) {
		t.Errorf("an unknown status should be rejected, got %v", err)
	}
}

// A conflict names the profiles involved, because an administrator reading it
// cannot do anything with a pair of UUIDs.
func TestConflictDetailNamesProfiles(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "CONFLICTED")

	a, err := svc.Create(ctx, profiles.NewProfile{Name: "Wants one", Settings: settings(), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Create(ctx, profiles.NewProfile{
		Name: "Wants two", Actor: "ops",
		Settings: []protocol.Setting{{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateRunning}},
	})
	if err != nil {
		t.Fatal(err)
	}

	detail := "profiles disagree about this setting: [" + a.ID.String() + " " + b.ID.String() + "]"
	if err := svc.RecordStatus(ctx, d.ID, a.ID, protocol.ProfileStatus{
		Version:  1,
		Settings: []protocol.SettingResult{{Identity: "service:spooler", Status: protocol.SettingConflict, Detail: detail}},
	}); err != nil {
		t.Fatal(err)
	}

	rows, _, err := st.Q().ListSettingStatus(ctx, a.ID, "", store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rows[0].Detail, "Wants one") || !strings.Contains(rows[0].Detail, "Wants two") {
		t.Fatalf("the detail should name both profiles, got %q", rows[0].Detail)
	}
	if strings.Contains(rows[0].Detail, a.ID.String()) {
		t.Errorf("the raw id should have been replaced, got %q", rows[0].Detail)
	}
}
