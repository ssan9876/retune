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

func newScript(t *testing.T, st *store.Store, name string) store.Script {
	t.Helper()
	s := store.Script{
		ID: uuid.Must(uuid.NewV7()), Name: name, CurrentVersion: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(), CreatedBy: "test",
	}
	if err := st.Q().CreateScript(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return s
}

func addVersion(t *testing.T, st *store.Store, id uuid.UUID, version int, body string) {
	t.Helper()
	err := st.Q().CreateScriptVersion(context.Background(), store.ScriptVersion{
		ScriptID: id, Version: version, Body: body, Hash: "h" + body,
		CreatedAt: time.Now(), CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScriptVersionsAreImmutable(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	s := newScript(t, st, "Install 7-Zip")
	addVersion(t, st, s.ID, 1, "first")
	addVersion(t, st, s.ID, 2, "second")

	v1, err := st.Q().GetScriptVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Body != "first" {
		t.Fatalf("version 1 body = %q, a later edit must not change it", v1.Body)
	}

	versions, err := st.Q().ListScriptVersions(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != 2 {
		t.Fatalf("want newest first, got %+v", versions)
	}

	if _, err := st.Q().GetScriptVersion(ctx, s.ID, 9); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound for a missing version, got %v", err)
	}
}

func TestScriptNamesAreUnique(t *testing.T) {
	st := storetest.New(t)
	newScript(t, st, "Duplicate")
	err := st.Q().CreateScript(context.Background(), store.Script{
		ID: uuid.Must(uuid.NewV7()), Name: "duplicate", CreatedAt: time.Now(),
		UpdatedAt: time.Now(), CreatedBy: "test",
	})
	if err == nil {
		t.Fatal("names should be unique regardless of case")
	}
}

func TestScriptRunsOutliveTheScript(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	s := newScript(t, st, "Temporary")
	addVersion(t, st, s.ID, 1, "body")
	d := newDevice(t, st.Q(), "RUNNER")

	run := store.ScriptRun{
		ID: uuid.Must(uuid.NewV7()), ScriptID: s.ID, Version: 1, DeviceID: d.ID,
		Status: store.RunSucceeded, Phase: store.PhaseScript, ExitCode: 0,
		Stdout: "done", StartedAt: time.Now(), FinishedAt: time.Now(),
	}
	if err := st.Q().InsertScriptRun(ctx, run); err != nil {
		t.Fatal(err)
	}

	if err := st.Q().DeleteScript(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	runs, total, err := st.Q().ListScriptRuns(ctx, s.ID, nil, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || runs[0].Stdout != "done" || runs[0].Hostname != "RUNNER" {
		t.Fatalf("runs should survive the script, got %d %+v", total, runs)
	}

	// The versions go with the script.
	if _, err := st.Q().GetScriptVersion(ctx, s.ID, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("versions should be deleted with the script, got %v", err)
	}
}

func TestListScriptRunsFiltersByDevice(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	s := newScript(t, st, "Fleet wide")
	a := newDevice(t, st.Q(), "A")
	b := newDevice(t, st.Q(), "B")

	for _, dev := range []uuid.UUID{a.ID, b.ID} {
		if err := st.Q().InsertScriptRun(ctx, store.ScriptRun{
			ID: uuid.Must(uuid.NewV7()), ScriptID: s.ID, Version: 1, DeviceID: dev,
			Status: store.RunSucceeded, Phase: store.PhaseScript,
			StartedAt: time.Now(), FinishedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, total, err := st.Q().ListScriptRuns(ctx, s.ID, nil, store.Page{}); err != nil || total != 2 {
		t.Fatalf("unfiltered: total %d err %v", total, err)
	}
	runs, total, err := st.Q().ListScriptRuns(ctx, s.ID, &b.ID, store.Page{})
	if err != nil || total != 1 || runs[0].Hostname != "B" {
		t.Fatalf("filtered by device: total %d runs %+v err %v", total, runs, err)
	}
}

func TestDeviceHasItem(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	d := newDevice(t, st.Q(), "ASSIGNED")
	other := newDevice(t, st.Q(), "UNASSIGNED")
	item := uuid.Must(uuid.NewV7())

	g := store.Group{
		ID: uuid.Must(uuid.NewV7()), Name: "Holders", Kind: store.GroupStatic,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.Q().CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := st.Q().AddGroupMember(ctx, g.ID, d.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: item,
		GroupID: g.ID, Mode: store.ModeInclude, CreatedAt: time.Now(), CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}

	if ok, err := st.Q().DeviceHasItem(ctx, d.ID, "script", item); err != nil || !ok {
		t.Fatalf("the assigned device should have the item: %v %v", ok, err)
	}
	if ok, err := st.Q().DeviceHasItem(ctx, other.ID, "script", item); err != nil || ok {
		t.Fatalf("an unassigned device must not: %v %v", ok, err)
	}
}

// TestEffectiveItemsUsesTheNewestIncludeOptions is the conflict rule: the same
// script reaching a device through two groups takes the newer assignment's
// options rather than refusing to run.
func TestEffectiveItemsUsesTheNewestIncludeOptions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	d := newDevice(t, st.Q(), "TWOGROUPS")
	item := uuid.Must(uuid.NewV7())

	mkGroup := func(name string) uuid.UUID {
		g := store.Group{
			ID: uuid.Must(uuid.NewV7()), Name: name, Kind: store.GroupStatic,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := st.Q().CreateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err := st.Q().AddGroupMember(ctx, g.ID, d.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		return g.ID
	}

	older, newer := mkGroup("Older"), mkGroup("Newer")
	base := time.Now().Add(-time.Hour)
	for _, a := range []store.Assignment{
		{ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: item, GroupID: older,
			Mode: store.ModeInclude, CreatedAt: base, CreatedBy: "t", Options: []byte(`{"frequency":"once"}`)},
		{ID: uuid.Must(uuid.NewV7()), ItemKind: "script", ItemID: item, GroupID: newer,
			Mode: store.ModeInclude, CreatedAt: base.Add(time.Minute), CreatedBy: "t",
			Options: []byte(`{"frequency":"recurring"}`)},
	} {
		if _, err := st.Q().CreateAssignment(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	items, err := st.Q().EffectiveItems(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("the item should appear once, got %d", len(items))
	}
	if string(items[0].Options) != `{"frequency": "recurring"}` &&
		string(items[0].Options) != `{"frequency":"recurring"}` {
		t.Fatalf("the newest include should supply the options, got %s", items[0].Options)
	}
}
