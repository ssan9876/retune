package scripts_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/scripts"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(st *store.Store) *scripts.Service {
	return &scripts.Service{Store: st, Now: time.Now}
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

func TestCreateStoresFirstVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	sc, err := svc.Create(ctx, scripts.NewScript{
		Name: "Install 7-Zip", Body: "winget install 7zip.7zip", Actor: "ops@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sc.CurrentVersion != 1 {
		t.Fatalf("current version = %d, want 1", sc.CurrentVersion)
	}
	v, err := svc.Version(ctx, sc.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v.Body != "winget install 7zip.7zip" || v.Hash == "" {
		t.Fatalf("version 1 = %+v", v)
	}
}

// Renaming a script must not make every device run it again, so only a changed
// body writes a new version.
func TestOnlyBodyChangesMakeVersions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	sc, err := svc.Create(ctx, scripts.NewScript{Name: "Original", Body: "one", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := svc.Update(ctx, sc.ID, scripts.NewScript{
		Name: "Renamed", Description: "now described", Body: "one", Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.CurrentVersion != 1 {
		t.Fatalf("renaming should not make a version, got %d", renamed.CurrentVersion)
	}

	edited, err := svc.Update(ctx, sc.ID, scripts.NewScript{Name: "Renamed", Body: "two", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if edited.CurrentVersion != 2 {
		t.Fatalf("a changed body should make version 2, got %d", edited.CurrentVersion)
	}

	// And the first version still says what it always said.
	v1, err := svc.Version(ctx, sc.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Body != "one" {
		t.Fatalf("version 1 body = %q, versions must be immutable", v1.Body)
	}

	// Adding a detection script is also a new version.
	withDetection, err := svc.Update(ctx, sc.ID, scripts.NewScript{
		Name: "Renamed", Body: "two", DetectionBody: "exit 0", Actor: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if withDetection.CurrentVersion != 3 {
		t.Fatalf("a changed detection script should make a version, got %d", withDetection.CurrentVersion)
	}
}

func TestCreateRejects(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	if _, err := svc.Create(ctx, scripts.NewScript{Name: "", Body: "x"}); !errors.Is(err, scripts.ErrBadRequest) {
		t.Errorf("an unnamed script should be rejected, got %v", err)
	}
	if _, err := svc.Create(ctx, scripts.NewScript{Name: "Empty", Body: "  "}); !errors.Is(err, scripts.ErrBadRequest) {
		t.Errorf("an empty body should be rejected, got %v", err)
	}
	if _, err := svc.Create(ctx, scripts.NewScript{Name: "Taken", Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, scripts.NewScript{Name: "taken", Body: "y"}); !errors.Is(err, scripts.ErrNameTaken) {
		t.Errorf("names should be unique regardless of case, got %v", err)
	}
}

func TestRecordRunUpdatesStatusAndHistory(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "REPORTER")

	sc, err := svc.Create(ctx, scripts.NewScript{Name: "Reported", Body: "x", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := svc.RecordRun(ctx, d.ID, sc.ID, protocol.ScriptRun{
		Version: 1, Status: protocol.ResultSucceeded, Phase: protocol.PhaseScript,
		ExitCode: 0, Stdout: "installed", StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rollup, err := st.Q().ItemStatusRollup(ctx, protocol.ItemKindScript, sc.ID, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemSucceeded] != 1 {
		t.Fatalf("rollup = %v", rollup)
	}
	statuses, _, err := st.Q().ListItemStatus(ctx, protocol.ItemKindScript, sc.ID, "", store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0].Version != 1 {
		t.Errorf("the status should record which version ran, got %d", statuses[0].Version)
	}

	// A later failure replaces the status but adds to the history.
	if err := svc.RecordRun(ctx, d.ID, sc.ID, protocol.ScriptRun{
		Version: 1, Status: protocol.ResultFailed, Phase: protocol.PhaseDetection,
		ExitCode: 3, StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	rollup, err = st.Q().ItemStatusRollup(ctx, protocol.ItemKindScript, sc.ID, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemFailed] != 1 || rollup[store.ItemSucceeded] != 0 {
		t.Fatalf("the latest run should decide the status, got %v", rollup)
	}
	runs, total, err := st.Q().ListScriptRuns(ctx, sc.ID, nil, store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("both runs should be kept, got %d", total)
	}
	if runs[0].Phase != protocol.PhaseDetection || runs[0].ExitCode != 3 {
		t.Fatalf("newest run = %+v", runs[0])
	}
	statuses, _, err = st.Q().ListItemStatus(ctx, protocol.ItemKindScript, sc.ID, "", store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0].Detail != "detection exited 3" {
		t.Errorf("the detail should say what failed, got %q", statuses[0].Detail)
	}
}

func TestRecordRunRejectsNonsense(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "BAD")
	sc, err := svc.Create(ctx, scripts.NewScript{Name: "Strict", Body: "x", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	if err := svc.RecordRun(ctx, d.ID, sc.ID, protocol.ScriptRun{
		Version: 1, Status: "exploded", Phase: protocol.PhaseScript, StartedAt: now, FinishedAt: now,
	}); !errors.Is(err, scripts.ErrBadRequest) {
		t.Errorf("an unknown status should be rejected, got %v", err)
	}
	if err := svc.RecordRun(ctx, d.ID, sc.ID, protocol.ScriptRun{
		Version: 1, Status: protocol.ResultSucceeded, Phase: "guessing", StartedAt: now, FinishedAt: now,
	}); !errors.Is(err, scripts.ErrBadRequest) {
		t.Errorf("an unknown phase should be rejected, got %v", err)
	}
}

func TestSetItemPending(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "WAITING")
	sc, err := svc.Create(ctx, scripts.NewScript{Name: "Interactive", Body: "x", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.SetItemPending(ctx, d.ID, sc.ID, 1, "running as the logged-in user is not supported yet"); err != nil {
		t.Fatal(err)
	}
	rollup, err := st.Q().ItemStatusRollup(ctx, protocol.ItemKindScript, sc.ID, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if rollup[store.ItemPending] != 1 {
		t.Fatalf("rollup = %v", rollup)
	}
}

func TestDeleteRemovesAssignmentsButKeepsRuns(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)
	d := device(t, st, "HISTORY")
	sc, err := svc.Create(ctx, scripts.NewScript{Name: "Doomed", Body: "x", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	g := store.Group{
		ID: uuid.Must(uuid.NewV7()), Name: "Targets", Kind: store.GroupStatic,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.Q().CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindScript, ItemID: sc.ID,
		GroupID: g.ID, Mode: store.ModeInclude, CreatedAt: time.Now(), CreatedBy: "t",
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := svc.RecordRun(ctx, d.ID, sc.ID, protocol.ScriptRun{
		Version: 1, Status: protocol.ResultSucceeded, Phase: protocol.PhaseScript,
		StartedAt: now, FinishedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, sc.ID, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, sc.ID); !errors.Is(err, scripts.ErrNotFound) {
		t.Errorf("the script should be gone, got %v", err)
	}
	assignments, err := st.Q().ListAssignments(ctx, protocol.ItemKindScript, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 0 {
		t.Errorf("its assignments should go with it, got %d", len(assignments))
	}
	if _, total, err := st.Q().ListScriptRuns(ctx, sc.ID, nil, store.Page{}, store.Unscoped); err != nil || total != 1 {
		t.Errorf("what happened on a machine stays true: total %d err %v", total, err)
	}
}
