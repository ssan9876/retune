package selfupdate_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
	"retune/internal/protocol"
	"retune/internal/release"
)

// testKey signs every build the fake server offers; syncers under test trust
// it unless a test says otherwise.
var testKey = mustKey()

func mustKey() release.PrivateKey {
	k, err := release.GenerateKey()
	if err != nil {
		panic(err)
	}
	return k
}

func trustTestKey() []release.PublicKey { return []release.PublicKey{testKey.Public()} }

// fakeClient stands in for the agent's server connection. downloadErr, when
// set, simulates a hash mismatch: the real client hashes as it streams, so
// it has already written whatever bytes it got by the time it discovers the
// mismatch, and this fake mirrors that rather than failing cleanly.
type fakeClient struct {
	version     string
	payload     []byte
	downloadErr error
	// onDownload, when set, runs inside DownloadAgentBinary, which is how a
	// test holds a Sync open in the middle of staging a build and watches what
	// else can still happen meanwhile.
	onDownload func()
	// signer, when set, signs the fake server's offer with a key other than
	// testKey -- how a test simulates a build signed by a key this agent was
	// not built to trust.
	signer *release.PrivateKey

	fetches   int
	downloads int
	reports   []protocol.AgentUpdateResult
}

func (c *fakeClient) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error) {
	c.fetches++
	sum := sha256.Sum256(c.payload)
	key := testKey
	if c.signer != nil {
		key = *c.signer
	}
	sig := release.Sign(key, release.Manifest{Version: c.version, SHA256: hex.EncodeToString(sum[:])})
	return protocol.AgentVersionResponse{
		Version:   c.version,
		SHA256:    hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(c.payload)),
		KeyID:     sig.KeyID,
		Signature: base64.StdEncoding.EncodeToString(sig.Signature),
	}, nil
}

func (c *fakeClient) DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error {
	c.downloads++
	_, _ = dst.Write(c.payload)
	if c.onDownload != nil {
		c.onDownload()
	}
	return c.downloadErr
}

func (c *fakeClient) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error {
	c.reports = append(c.reports, r)
	return nil
}

// agentItem builds a check-in item for an agent build. A build is immutable,
// so its item version is always 1; opts, when nil, marshals the defaults.
func agentItem(id string, opts *protocol.AgentOptions) protocol.Item {
	o := protocol.DefaultAgentOptions()
	if opts != nil {
		o = *opts
	}
	raw, err := o.Marshal()
	if err != nil {
		panic(err)
	}
	return protocol.Item{Kind: protocol.ItemKindAgent, ID: id, Version: 1, Options: raw}
}

// A clean update: the build is downloaded, verified, staged, and the
// supervisor is handed off to. The record's FromBinPath/FromArgs must come
// from the live service, not be left empty -- an empty FromArgs would strip
// --data-dir from a hand-installed service on repoint.
func TestSyncStagesAndHandsOff(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`, args: []string{"--data-dir", dir}}
	var spawned string
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(p string) error { spawned = p; return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if spawned == "" {
		t.Fatal("the supervisor should have been handed off to")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0", selfupdate.BinName)); err != nil {
		t.Errorf("the new build should be staged: %v", err)
	}
	rec, found, _ := selfupdate.ReadRecord(dir)
	if !found || rec.ToVersion != "2.0.0" || rec.Status != selfupdate.StatusPending {
		t.Fatalf("a pending record should describe the attempt, got %+v", rec)
	}
	if rec.FromVersion != "1.0.0" {
		t.Errorf("the record must remember what to go back to, got %q", rec.FromVersion)
	}
	wantBinPath, wantArgs, _ := control.Config()
	if rec.FromBinPath != wantBinPath {
		t.Errorf("FromBinPath must come from the live service, got %q want %q", rec.FromBinPath, wantBinPath)
	}
	if len(rec.FromArgs) != len(wantArgs) || rec.FromArgs[0] != wantArgs[0] || rec.FromArgs[1] != wantArgs[1] {
		t.Errorf("FromArgs must come from the live service, got %v want %v", rec.FromArgs, wantArgs)
	}
}

// Proof of life. The supervisor polls the record for a succeeded status and
// nothing else writes one, so without this the deadline always expires and
// every update rolls back.
func TestCheckedInMarksThisBuildsAttemptSucceeded(t *testing.T) {
	dir := t.TempDir()
	rec := selfupdate.Record{
		ItemID: "v1", FromVersion: "1.0.0", ToVersion: "2.0.0",
		Deadline: time.Now().Add(time.Minute), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	s := &selfupdate.Syncer{Dir: dir, Running: "2.0.0", Injected: true, Trusted: trustTestKey(), Log: slog.New(slog.DiscardHandler)}

	if err := s.CheckedIn(); err != nil {
		t.Fatal(err)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusSucceeded {
		t.Fatalf("the attempt this build was staged for should be succeeded, got %+v", got)
	}
}

// A check-in only proves the build it came from. Anything else the record
// might describe is somebody else's business.
func TestCheckedInLeavesEveryOtherRecordAlone(t *testing.T) {
	cases := map[string]struct {
		rec     selfupdate.Record
		running string
	}{
		"an attempt to stage a different version": {
			rec: selfupdate.Record{
				ToVersion: "3.0.0", Status: selfupdate.StatusPending,
				Deadline: time.Now().Add(time.Minute),
			},
			running: "2.0.0",
		},
		"an attempt that was already rolled back": {
			rec:     selfupdate.Record{ToVersion: "2.0.0", Status: selfupdate.StatusRolledBack},
			running: "2.0.0",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := selfupdate.WriteRecord(dir, tc.rec); err != nil {
				t.Fatal(err)
			}
			s := &selfupdate.Syncer{Dir: dir, Running: tc.running, Injected: true, Trusted: trustTestKey(), Log: slog.New(slog.DiscardHandler)}

			if err := s.CheckedIn(); err != nil {
				t.Fatal(err)
			}
			got, _, _ := selfupdate.ReadRecord(dir)
			if got.Status != tc.rec.Status {
				t.Errorf("status = %q, want it untouched at %q", got.Status, tc.rec.Status)
			}
		})
	}
}

// The ordinary case: no update is under way, and a check-in must not invent a
// record for one.
func TestCheckedInWithNoRecordWritesNothing(t *testing.T) {
	dir := t.TempDir()
	s := &selfupdate.Syncer{Dir: dir, Running: "1.0.0", Injected: true, Trusted: trustTestKey(), Log: slog.New(slog.DiscardHandler)}

	if err := s.CheckedIn(); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a check-in with nothing under way should leave no record behind")
	}
}

// A payload whose hash does not match is refused, nothing is staged, and the
// supervisor is never started.
func TestSyncRefusesAMismatchedHash(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), downloadErr: errors.New("sha256 mismatch")}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	var spawned bool
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { spawned = true; return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if spawned {
		t.Error("a build that failed verification must never be handed to the supervisor")
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("nothing should be pending")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0")); err == nil {
		t.Error("a mismatched download must leave nothing behind, wrong bytes are worse than none")
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the mismatch should be reported, got %+v", c.reports)
	}
}

// A rollback left by a previous attempt is reported, once, and then forgotten.
// Nothing else can report it: the supervisor that decided is gone.
func TestSyncReportsAPendingRollback(t *testing.T) {
	dir := t.TempDir()
	rec := selfupdate.Record{
		FromVersion: "1.0.0", ToVersion: "2.0.0",
		Status: selfupdate.StatusRolledBack, Detail: "the new agent never checked in",
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeClient{version: "1.0.0"}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now, Rollback: &rec,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Fatalf("the rollback should be reported exactly once, got %+v", c.reports)
	}
	if c.reports[0].RolledBackFrom != "2.0.0" || c.reports[0].Status != protocol.ResultFailed {
		t.Errorf("report = %+v", c.reports[0])
	}
	// The record stays, marked as reported. It is the only memory that this
	// version failed here, and removing it would let the very next item in
	// the very same check-in decide to install it all over again.
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusRolledBack || !got.Reported {
		t.Fatalf("a reported rollback should stay on disk, marked reported, got %+v (found=%v)", got, found)
	}

	// A second cycle must not report it again.
	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Errorf("it must not be reported twice, got %d", len(c.reports))
	}
}

// The loop this prevents: reporting a rollback used to delete the record, so
// the same check-in's item list found no memory of the failure, decided to
// update, and stopped, swapped, waited and rolled back the same broken build
// again -- on every device in the group, for ever.
func TestSyncDoesNotRetryAVersionItJustReportedRolledBack(t *testing.T) {
	newSyncer := func(t *testing.T, dir string, c *fakeClient, rec *selfupdate.Record, spawned *int) *selfupdate.Syncer {
		t.Helper()
		return &selfupdate.Syncer{
			Dir: dir, Client: c, Control: &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`},
			Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
			Log: slog.New(slog.DiscardHandler), Now: time.Now, Rollback: rec,
			Spawn: func(string) error { *spawned++; return nil },
		}
	}
	rolledBack := selfupdate.Record{
		ItemID: "v1", FromVersion: "1.0.0", ToVersion: "2.0.0",
		Status: selfupdate.StatusRolledBack, Detail: "the new agent never checked in",
	}

	t.Run("the same version is refused", func(t *testing.T) {
		dir := t.TempDir()
		rec := rolledBack
		if err := selfupdate.WriteRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		var spawned int
		c := &fakeClient{version: "2.0.0", payload: []byte("the build that failed")}
		s := newSyncer(t, dir, c, &rec, &spawned)

		if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
			t.Fatal(err)
		}
		if spawned != 0 {
			t.Errorf("the version that was just reported rolled back must not be installed again, got %d hand-offs", spawned)
		}
		got, found, _ := selfupdate.ReadRecord(dir)
		if !found || got.Status != selfupdate.StatusRolledBack || !got.Reported {
			t.Fatalf("the refusal must stay on disk, got %+v (found=%v)", got, found)
		}
	})

	t.Run("a different version still gets through", func(t *testing.T) {
		dir := t.TempDir()
		rec := rolledBack
		if err := selfupdate.WriteRecord(dir, rec); err != nil {
			t.Fatal(err)
		}
		var spawned int
		c := &fakeClient{version: "3.0.0", payload: []byte("a build worth trying")}
		s := newSyncer(t, dir, c, &rec, &spawned)

		if err := s.Sync(context.Background(), []protocol.Item{agentItem("v2", nil)}); err != nil {
			t.Fatal(err)
		}
		if spawned != 1 {
			t.Errorf("a version that has not failed here must still be attempted, got %d hand-offs", spawned)
		}
	})
}

// An unstamped build refuses outright, does not download, and says why -- so
// somebody can see that the fleet is not updating and know the reason.
func TestSyncRefusesWithoutAnInjectedVersion(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "0.1.0-dev", Injected: false, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("it must not download, got %d downloads", c.downloads)
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the refusal should be reported, got %+v", c.reports)
	}
	if !strings.Contains(c.reports[0].Detail, "injected") {
		t.Errorf("the detail should say why, got %q", c.reports[0].Detail)
	}
}

// Items of other kinds are ignored, which is how an older agent copes with a
// newer server.
func TestSyncIgnoresOtherKinds(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	item := protocol.Item{Kind: protocol.ItemKindScript, ID: "some-script", Version: 1}
	if err := s.Sync(context.Background(), []protocol.Item{item}); err != nil {
		t.Fatal(err)
	}
	if c.fetches != 0 || c.downloads != 0 {
		t.Errorf("nothing should have been fetched or downloaded, got fetches=%d downloads=%d", c.fetches, c.downloads)
	}
	if len(c.reports) != 0 {
		t.Errorf("nothing should have been reported, got %+v", c.reports)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("nothing should have been recorded")
	}
}

// Control is nil on a platform where NewController returned ErrWindowsOnly.
// Pretending to act would be worse than refusing: without a live service to
// read, the record it would write strips --data-dir on repoint and can brick
// a hand-installed service on rollback. So it refuses outright, before any
// download.
func TestSyncRefusesWithNoController(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: nil, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("it must not download without a controller, got %d downloads", c.downloads)
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the refusal should be reported, got %+v", c.reports)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("nothing should have been recorded")
	}
}

// The session starts every syncer on its own goroutine once per check-in and
// does not wait for the previous cycle to finish, so two Sync calls really can
// overlap on a slow download. The lock inside Sync is what keeps that from
// staging and handing off the same build twice: the second call waits, finds
// the pending record the first one wrote, and Decide answers "already under
// way". The second call is started while the first is demonstrably inside its
// download, so the overlap is the test's doing and not a matter of timing.
func TestSyncSerialisesConcurrentCalls(t *testing.T) {
	dir := t.TempDir()
	downloading, release := make(chan struct{}), make(chan struct{})
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	c.onDownload = func() {
		close(downloading)
		<-release
	}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`, args: []string{"--data-dir", dir}}

	var mu sync.Mutex
	var spawns int
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error {
			mu.Lock()
			defer mu.Unlock()
			spawns++
			return nil
		},
	}

	items := []protocol.Item{agentItem("v1", nil)}
	sync1 := func() {
		if err := s.Sync(context.Background(), items); err != nil {
			t.Error(err)
		}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); sync1() }()

	<-downloading
	wg.Add(1)
	go func() { defer wg.Done(); sync1() }()
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if spawns != 1 {
		t.Errorf("overlapping check-ins must hand off exactly once, got %d", spawns)
	}
	if c.fetches != 2 {
		t.Errorf("both cycles should have run, the second one after the first let go, got %d fetches", c.fetches)
	}
}

// A rollback report can fail for several check-ins before it gets through, and
// in the meantime a different build can be assigned and staged. Marking the
// report done must not write the old rollback back over that live pending
// attempt -- which is what rewriting the startup copy of the record whole would
// do, losing the only thing a supervisor and a rollback have to go on.
func TestReportingARollbackDoesNotClobberANewerAttempt(t *testing.T) {
	dir := t.TempDir()
	rolledBack := selfupdate.Record{
		ItemID: "v1", FromVersion: "1.0.0", ToVersion: "2.0.0",
		Status: selfupdate.StatusRolledBack, Detail: "the new agent never checked in",
	}
	// What is actually on disk by the time the report succeeds: a newer build,
	// staged and under way.
	staged := selfupdate.Record{
		ItemID: "v2", FromVersion: "1.0.0", ToVersion: "3.0.0",
		Deadline: time.Now().Add(time.Minute), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, staged); err != nil {
		t.Fatal(err)
	}
	c := &fakeClient{version: "1.0.0"}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(), Rollback: &rolledBack,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Fatalf("the rollback should still be reported, got %+v", c.reports)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusPending || got.ToVersion != "3.0.0" {
		t.Fatalf("the live attempt must survive the report, got %+v (found=%v)", got, found)
	}
}

// A check-in must not wait on a download. Sync holds its lock across the whole
// staging of a build, which can take as long as the download timeout, and the
// session calls CheckedIn inline on the check-in path: sharing one lock would
// mean a device mid-download stops checking in altogether -- no inventory, no
// commands, nothing -- which is the very thing dispatching syncers in the
// background exists to prevent. The record has its own lock for that reason.
func TestCheckedInIsNotBlockedByASyncThatIsDownloading(t *testing.T) {
	dir := t.TempDir()
	// A previous update to the build now running, whose proof of life has not
	// landed yet, while a newer build is already assigned.
	rec := selfupdate.Record{
		ItemID: "v0", FromVersion: "0.9.0", ToVersion: "1.0.0",
		Deadline: time.Now().Add(time.Minute), Status: selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}

	downloading, release := make(chan struct{}), make(chan struct{})
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	c.onDownload = func() {
		close(downloading)
		<-release
	}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`, args: []string{"--data-dir", dir}}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
			t.Error(err)
		}
	}()
	<-downloading

	done := make(chan error, 1)
	go func() { done <- s.CheckedIn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		// Only ever reached by an implementation that shares one lock; it
		// bounds the failure instead of hanging the suite until the harness
		// gives up.
		t.Fatal("CheckedIn waited on a download; a device mid-update would stop checking in")
	}

	// And the proof actually landed, before the download was let go.
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusSucceeded || got.ToVersion != "1.0.0" {
		t.Fatalf("the pending attempt for the running build should be succeeded, got %+v", got)
	}

	close(release)
	wg.Wait()
}

// A supervisor that could not even stop the service writes rolled_back while
// this process keeps running: it was never restarted, so nothing handed it a
// Rollback at startup. Waiting for the next service restart to report that
// would leave the console staring at a device that looks fine, so Sync adopts
// whatever unreported rollback it finds on disk.
func TestSyncAdoptsAnUnreportedRollbackFromDisk(t *testing.T) {
	dir := t.TempDir()
	rec := selfupdate.Record{
		ItemID: "v1", FromVersion: "1.0.0", ToVersion: "2.0.0",
		Status: selfupdate.StatusRolledBack, Detail: "the service would not stop: it is wedged",
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeClient{version: "1.0.0"}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 || c.reports[0].RolledBackFrom != "2.0.0" {
		t.Fatalf("the rollback on disk should have been reported, got %+v", c.reports)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || !got.Reported {
		t.Fatalf("it should be marked reported, got %+v (found=%v)", got, found)
	}

	// And not again on the next cycle.
	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Errorf("it must not be reported twice, got %d", len(c.reports))
	}
}

// A hand-off that fails after the build is staged and the record written
// must not wedge the device: without this cleanup, Decide would answer
// "already under way" forever, with no supervisor left to ever resolve it.
func TestSyncAbandonsAFailedHandOff(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return errors.New("could not start the supervisor process") },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a failed hand-off must not leave a pending record behind")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0")); err == nil {
		t.Error("a failed hand-off must not leave the staged build behind")
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the failed hand-off should be reported, got %+v", c.reports)
	}
}

// The server verified the signature at upload, but the server is what this
// check does not trust: a build signed by a key this agent was not built to
// trust is refused after download, reported, and leaves no staged binary
// behind -- but a refused record is written, so the same build is not
// downloaded again on the next check-in.
func TestSyncRefusesABuildSignedByAnUntrustedKey(t *testing.T) {
	dir := t.TempDir()
	other := mustKey()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), signer: &other}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	var spawned bool
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { spawned = true; return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if spawned {
		t.Error("an unverified build must never be handed to the supervisor")
	}
	rec, found, _ := selfupdate.ReadRecord(dir)
	if !found || rec.Status != selfupdate.StatusRefused || rec.ItemID != "v1" {
		t.Fatalf("a refused record should remember this build, got %+v (found=%v)", rec, found)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0")); err == nil {
		t.Error("an unverified download must leave nothing behind")
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the refusal should be reported, got %+v", c.reports)
	}
	if !strings.Contains(c.reports[0].Detail, "signature did not verify") ||
		!strings.Contains(c.reports[0].Detail, other.Public().ID()) {
		t.Errorf("the detail should say why and name the key, got %q", c.reports[0].Detail)
	}
}

// A build stamped with no trust list cannot verify anything, so it must not
// download anything. Like the unstamped case, it says so on every check-in.
func TestSyncRefusesWhenTheBuildTrustsNoKeys(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: &fakeControl{}, Running: "1.0.0", Injected: true, Trusted: nil,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("it must not download, got %d downloads", c.downloads)
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the refusal should be reported, got %+v", c.reports)
	}
	if !strings.Contains(c.reports[0].Detail, "no trusted release keys") {
		t.Errorf("the detail should say why, got %q", c.reports[0].Detail)
	}
}

// A build refused on its signature is never downloaded at all - the
// signature is checked against the definition before a byte is fetched - and
// the next check-in finds the refused record and returns before even fetching
// the definition, for as long as the bad build stays assigned.
func TestARefusedBuildIsNotDownloadedAgain(t *testing.T) {
	dir := t.TempDir()
	other := mustKey()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), signer: &other}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("downloads = %d, want none", c.downloads)
	}
	if c.fetches != 1 {
		t.Errorf("fetches = %d, want 1", c.fetches)
	}
	if len(c.reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", c.reports)
	}
	rec, found, _ := selfupdate.ReadRecord(dir)
	if !found || rec.Status != selfupdate.StatusRefused || rec.ItemID != "v1" {
		t.Fatalf("record = %+v (found=%v), want a refused record for item v1", rec, found)
	}
}

// A refusal of one item must not block a different item: the memory is keyed
// on item id, and a differently-signed build under a different item id is
// still worth trying.
func TestARefusedBuildDoesNotBlockADifferentItem(t *testing.T) {
	dir := t.TempDir()
	other := mustKey()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), signer: &other}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}

	c2 := &fakeClient{version: "3.0.0", payload: []byte("good bytes")}
	var spawned bool
	s2 := &selfupdate.Syncer{
		Dir: dir, Client: c2, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { spawned = true; return nil },
	}
	if err := s2.Sync(context.Background(), []protocol.Item{agentItem("v2", nil)}); err != nil {
		t.Fatal(err)
	}
	if c2.downloads != 1 {
		t.Errorf("downloads = %d, want 1", c2.downloads)
	}
	if !spawned {
		t.Error("a different item's trusted build should be handed off")
	}
}

// A hash mismatch is transient, not remembered: the next check-in is its
// retry, unlike a refused signature.
func TestAHashMismatchIsRetried(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), downloadErr: errors.New("sha256 mismatch")}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 2 {
		t.Errorf("downloads = %d, want 2", c.downloads)
	}
}

// A device already on its assigned version must stay quiet even with no
// trust list configured: there is nothing to download or verify, so the
// missing trust list is not what is stopping it, and reporting "failed"
// every check-in here would flap against the server's own inference that
// this device has succeeded.
func TestSyncStaysQuietWhenAlreadyOnTheAssignedVersionWithNoTrustList(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: &fakeControl{}, Running: "2.0.0", Injected: true, Trusted: nil,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("it must not download, got %d downloads", c.downloads)
	}
	if len(c.reports) != 0 {
		t.Errorf("staying on the assigned version must not be reported, got %+v", c.reports)
	}
}

// The version names a folder under bin, and it comes from the server. One
// that would climb out of bin is refused before anything is created, fetched
// or removed.
func TestAVersionThatIsNotAVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: `..\..\Users`, payload: []byte("bytes")}
	control := &fakeControl{binPath: `C:\Program Files\Retune\retune-agent.exe`}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Control: control, Running: "1.0.0", Injected: true, Trusted: trustTestKey(),
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { return nil },
	}
	// Sync logs a failed item rather than failing the whole cycle; what
	// matters is that nothing was downloaded or created, and that it said so.
	_ = s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)})
	if c.downloads != 0 {
		t.Errorf("downloads = %d, want none", c.downloads)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin")); !os.IsNotExist(err) {
		t.Errorf("nothing should be created under bin, got %v", err)
	}
	if len(c.reports) != 1 || !strings.Contains(c.reports[0].Detail, "not a valid version") {
		t.Errorf("the refusal should be reported, got %+v", c.reports)
	}
}
