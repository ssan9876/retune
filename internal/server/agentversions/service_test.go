package agentversions_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/agentversions"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(t *testing.T, st *store.Store) *agentversions.Service {
	t.Helper()
	return &agentversions.Service{Store: st, Artifacts: artifacts.Store{Dir: t.TempDir()}}
}

func TestUploadRecordsTheHashItComputed(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	v, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.2.3", Actor: "ops"},
		strings.NewReader("a pretend agent"))
	if err != nil {
		t.Fatal(err)
	}
	if v.SHA256 == "" || v.SizeBytes != int64(len("a pretend agent")) {
		t.Fatalf("version = %+v", v)
	}

	r, size, err := svc.Open(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if size != v.SizeBytes {
		t.Errorf("Open reported %d bytes, metadata says %d", size, v.SizeBytes)
	}
	if body, _ := io.ReadAll(r); string(body) != "a pretend agent" {
		t.Errorf("read back %q", body)
	}
}

// The same version twice is a mistake. Accepting it would mean two devices
// could install different bytes for what the console calls one build.
func TestUploadRefusesADuplicateVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	if _, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.0.0", Actor: "ops"},
		strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.0.0", Actor: "ops"},
		strings.NewReader("second"))
	if !errors.Is(err, agentversions.ErrVersionTaken) {
		t.Fatalf("want ErrVersionTaken, got %v", err)
	}
}

func TestUploadRejectsBadInput(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	for name, in := range map[string]agentversions.NewVersion{
		"no version":        {Actor: "ops"},
		"a path in version": {Version: "../evil", Actor: "ops"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Upload(ctx, in, strings.NewReader("x")); !errors.Is(err, agentversions.ErrBadRequest) {
				t.Fatalf("want ErrBadRequest, got %v", err)
			}
		})
	}
}

// Deleting a build removes its bytes and its assignments, so no device is left
// being told to install something that no longer exists.
func TestDeleteRemovesBytesAndAssignments(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	v, err := svc.Upload(ctx, agentversions.NewVersion{Version: "2.0.0", Actor: "ops"},
		strings.NewReader("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: v.ID,
		GroupID: store.BuiltinGroupID, Mode: store.ModeInclude, CreatedAt: time.Now(), CreatedBy: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, v.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Open(ctx, v.ID); err == nil {
		t.Error("the bytes should be gone")
	}
	rows, err := st.Q().ListAssignments(ctx, protocol.ItemKindAgent, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("assignments should have gone too, got %+v", rows)
	}
}
