package agentversions_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/agentversions"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(t *testing.T, st *store.Store) (*agentversions.Service, release.PrivateKey) {
	t.Helper()
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &agentversions.Service{
		Store: st, Artifacts: artifacts.Store{Dir: t.TempDir()},
		ReleaseKeys: []release.PublicKey{priv.Public()},
	}, priv
}

// signed builds a valid NewVersion for body under priv.
func signed(priv release.PrivateKey, version, body, actor string) agentversions.NewVersion {
	sum := sha256.Sum256([]byte(body))
	sig := release.Sign(priv, release.Manifest{Version: version, SHA256: hex.EncodeToString(sum[:])})
	return withSignature(version, actor, sig)
}

// withSignature builds a NewVersion carrying sig's header form, for tests
// that need to construct or mutate the release.Signature directly rather
// than through Sign.
func withSignature(version, actor string, sig release.Signature) agentversions.NewVersion {
	return agentversions.NewVersion{
		Version: version, Actor: actor,
		SignatureHeader: signatureHeader(sig),
	}
}

// signatureHeader is the base64-of-JSON form the X-Retune-Signature header
// carries; Upload decodes it the same way a real request's header does.
func signatureHeader(sig release.Signature) string {
	b, err := json.Marshal(sig)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestUploadRecordsTheHashItComputed(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	v, err := svc.Upload(ctx, signed(priv, "1.2.3", "a pretend agent 1.2.3", "ops"),
		strings.NewReader("a pretend agent 1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	if v.SHA256 == "" || v.SizeBytes != int64(len("a pretend agent 1.2.3")) {
		t.Fatalf("version = %+v", v)
	}
	if v.KeyID != priv.Public().ID() {
		t.Errorf("KeyID = %q, want %q", v.KeyID, priv.Public().ID())
	}
	if v.Signature == "" {
		t.Error("Signature should not be empty")
	}

	r, size, err := svc.Open(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if size != v.SizeBytes {
		t.Errorf("Open reported %d bytes, metadata says %d", size, v.SizeBytes)
	}
	if body, _ := io.ReadAll(r); string(body) != "a pretend agent 1.2.3" {
		t.Errorf("read back %q", body)
	}
}

// The same version twice is a mistake. Accepting it would mean two devices
// could install different bytes for what the console calls one build.
func TestUploadRefusesADuplicateVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	if _, err := svc.Upload(ctx, signed(priv, "1.0.0", "first 1.0.0", "ops"),
		strings.NewReader("first 1.0.0")); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Upload(ctx, signed(priv, "1.0.0", "second 1.0.0", "ops"),
		strings.NewReader("second 1.0.0"))
	if !errors.Is(err, agentversions.ErrVersionTaken) {
		t.Fatalf("want ErrVersionTaken, got %v", err)
	}
	assertRejectionAudited(t, st, ctx)
}

// assertRejectionAudited fails the test unless at least one
// agent_version.rejected entry exists. It is used by tests whose refusal
// happens before the signature-table's own audit count, so it does not
// count entries the way TestUploadRejections does.
func assertRejectionAudited(t *testing.T, st *store.Store, ctx context.Context) {
	t.Helper()
	entries, _, err := st.Q().ListAuditPage(ctx, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "agent_version.rejected" {
			return
		}
	}
	t.Error("a refused upload should write an agent_version.rejected audit entry")
}

func TestUploadRejectsBadInput(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	for name, in := range map[string]agentversions.NewVersion{
		"no version":        signed(priv, "", "x", "ops"),
		"a path in version": signed(priv, "../evil", "x", "ops"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Upload(ctx, in, strings.NewReader("x")); !errors.Is(err, agentversions.ErrBadRequest) {
				t.Fatalf("want ErrBadRequest, got %v", err)
			}
		})
	}
}

// A bad version string that slips past every check earlier in Upload is
// still caught, since it is Artifacts.Put that knows which strings are
// usable as a directory name -- and that refusal must be audited exactly
// like every other rejection, not returned as a silent 400.
func TestUploadAuditsABadVersionFromPut(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	before := countRejections(t, st, ctx)
	_, err := svc.Upload(ctx, signed(priv, "../evil", "x", "ops"), strings.NewReader("x"))
	if !errors.Is(err, agentversions.ErrBadRequest) {
		t.Fatalf("want ErrBadRequest, got %v", err)
	}
	if got := countRejections(t, st, ctx) - before; got != 1 {
		t.Errorf("%d new rejection audit entries, want 1", got)
	}
}

// countRejections returns how many agent_version.rejected audit entries
// exist, so a test can check that exactly one more was written by the call
// under test.
func countRejections(t *testing.T, st *store.Store, ctx context.Context) int {
	t.Helper()
	entries, _, err := st.Q().ListAuditPage(ctx, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == "agent_version.rejected" {
			n++
		}
	}
	return n
}

// A concurrent upload of the same version can pass Upload's own pre-check
// before either writes bytes; Artifacts.Put's ErrExists is what actually
// catches that collision, and the refusal must be audited exactly like every
// other rejection, not silently returned as ErrVersionTaken.
func TestUploadAuditsAConcurrentUploadRace(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	// Pre-seed the version directory the way a racing upload would, for a
	// version the DB has not seen yet -- so Upload's pre-check passes and
	// Put is what discovers the collision.
	if _, _, err := svc.Artifacts.Put("9.0.0", strings.NewReader("already there"), 1<<20); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Upload(ctx, signed(priv, "9.0.0", "new bytes", "ops"), strings.NewReader("new bytes"))
	if !errors.Is(err, agentversions.ErrVersionTaken) {
		t.Fatalf("want ErrVersionTaken, got %v", err)
	}
	assertRejectionAudited(t, st, ctx)
}

// With no release keys configured, an upload is refused before its signature
// header is even looked at: nothing is silently accepted just because a
// caller forgot to wire ReleaseKeys, however good the signature it carries.
func TestUploadRefusesWithoutReleaseKeys(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)
	svc.ReleaseKeys = nil
	_, err := svc.Upload(ctx, signed(priv, "1.0.0", "b", "ops"), strings.NewReader("b"))
	if !errors.Is(err, agentversions.ErrNoReleaseKeys) {
		t.Fatalf("want ErrNoReleaseKeys, got %v", err)
	}
	assertRejectionAudited(t, st, ctx)
}

func TestUploadRejections(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)
	other, _ := release.GenerateKey()

	// stored marks the rejections that come after the bytes are written, the
	// only ones for which "nothing left behind" says anything: the others are
	// refused before a byte reaches the artifact store.
	cases := map[string]struct {
		in     agentversions.NewVersion
		body   string
		want   string
		stored bool
	}{
		"no signature header": {
			in: agentversions.NewVersion{Version: "1.0.0", Actor: "ops"},
			body: "b", want: "carried no " + agentversions.SignatureHeader + " header",
		},
		"header is not base64": {
			in: agentversions.NewVersion{Version: "1.0.0", Actor: "ops", SignatureHeader: "!!not base64"},
			body: "b", want: agentversions.SignatureHeader + " is not base64",
		},
		"header is not a sidecar": {
			in: agentversions.NewVersion{
				Version: "1.0.0", Actor: "ops",
				SignatureHeader: base64.StdEncoding.EncodeToString([]byte("not json")),
			},
			body: "b", want: agentversions.SignatureHeader + ":",
		},
		"notes too long": {
			in: func() agentversions.NewVersion {
				n := signed(priv, "1.0.0", "b", "ops")
				n.Notes = strings.Repeat("x", agentversions.MaxNotesLength+1)
				return n
			}(), body: "b", want: "notes may be at most",
		},
		"unknown key": {
			in: signed(other, "1.0.0", "b", "ops"), body: "b", want: "not a configured release key",
		},
		"bytes differ from the signed hash": {
			in: signed(priv, "1.0.0", "b", "ops"), body: "not b", want: "hash to", stored: true,
		},
		"declared version differs from the signed one": {
			in: func() agentversions.NewVersion {
				n := signed(priv, "1.0.0", "b", "ops")
				n.Version = "1.0.1"
				return n
			}(), body: "b", want: "does not match the signed version", stored: true,
		},
		"forged signature": {
			in: func() agentversions.NewVersion {
				sum := sha256.Sum256([]byte("b"))
				sig := release.Sign(priv, release.Manifest{Version: "1.0.0", SHA256: hex.EncodeToString(sum[:])})
				sig.Signature[0] ^= 1
				return withSignature("1.0.0", "ops", sig)
			}(), body: "b", want: "did not verify", stored: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.Upload(ctx, tc.in, strings.NewReader(tc.body))
			if !errors.Is(err, agentversions.ErrBadRequest) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want ErrBadRequest containing %q, got %v", tc.want, err)
			}
			if !tc.stored {
				return
			}
			if _, _, err := svc.Artifacts.Open(tc.in.Version); err == nil {
				t.Error("a refused upload must not leave its bytes behind")
			}
		})
	}

	// Every rejection is audited: a refused upload is the event signing exists
	// to notice.
	entries, _, err := st.Q().ListAuditPage(ctx, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	rejected := 0
	for _, e := range entries {
		if e.Action == "agent_version.rejected" {
			rejected++
		}
	}
	if rejected != len(cases) {
		t.Errorf("%d rejection audit entries, want %d", rejected, len(cases))
	}
}

// The notes limit counts characters, not bytes: notes written in a script
// that needs several bytes a character get the same room as ASCII.
func TestUploadAcceptsNotesAtTheLimit(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)
	in := signed(priv, "1.0.0", "b", "ops")
	in.Notes = strings.Repeat("é", agentversions.MaxNotesLength)
	v, err := svc.Upload(ctx, in, strings.NewReader("b"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Notes != in.Notes {
		t.Error("the notes should be stored as sent")
	}
}

// Deleting a build removes its bytes and its assignments, so no device is left
// being told to install something that no longer exists.
func TestDeleteRemovesBytesAndAssignments(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	v, err := svc.Upload(ctx, signed(priv, "2.0.0", "bytes 2.0.0", "ops"),
		strings.NewReader("bytes 2.0.0"))
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

func newDevice(t *testing.T, q *store.Queries, hostname string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: "SN-" + hostname, SMBIOSUUID: "U-" + hostname,
		Status: store.DeviceActive, CertSerial: "c-" + hostname, CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

// RecordResult is what the console's per-device status comes from, so what it
// writes has to be readable back through the same query the console uses.
func TestRecordResultSetsItemStatus(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	v, err := svc.Upload(ctx, signed(priv, "4.0.0", "bytes 4.0.0", "ops"),
		strings.NewReader("bytes 4.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	d := newDevice(t, st.Q(), "PC-RESULT")

	if err := svc.RecordResult(ctx, d.ID, v.ID, protocol.AgentUpdateResult{
		Version: "4.0.0", Status: protocol.ResultSucceeded, Detail: "running 4.0.0",
	}); err != nil {
		t.Fatal(err)
	}

	rows, _, err := st.Q().ListItemStatus(ctx, protocol.ItemKindAgent, v.ID, "", store.Page{}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one status row, got %+v", rows)
	}
	got := rows[0]
	if got.Status != store.ItemSucceeded || got.Detail != "running 4.0.0" || got.Version != 1 {
		t.Errorf("status = %+v, want succeeded, detail %q, version 1", got, "running 4.0.0")
	}
}
