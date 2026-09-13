package apps_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// fakeWinget answers with canned results, so installs can be tested without
// installing anything.
type fakeWinget struct {
	mu        sync.Mutex
	installed bool
	version   string
	calls     []string
	detects   int
	// installErr is the exit code the install should produce.
	installErr int
	// detectErr, when set, is returned as Result.Err starting from the
	// detectFailFrom'th call to Detect (1-indexed; 0 means every call), so a
	// test can make only a later detection fail without touching the first.
	detectErr      error
	detectFailFrom int
}

func (f *fakeWinget) Detect(context.Context, string) (bool, string, apps.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "detect")
	f.detects++
	if f.detectErr != nil && (f.detectFailFrom == 0 || f.detects >= f.detectFailFrom) {
		return false, "", apps.Result{Err: f.detectErr}
	}
	return f.installed, f.version, apps.Result{}
}

func (f *fakeWinget) Install(context.Context, protocol.AppVersionResponse) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "install")
	if f.installErr == 0 {
		f.installed, f.version = true, "26.03"
	}
	return apps.Result{ExitCode: f.installErr}
}

func (f *fakeWinget) Uninstall(context.Context, string) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "uninstall")
	f.installed, f.version = false, ""
	return apps.Result{}
}

func (f *fakeWinget) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeClient struct {
	version protocol.AppVersionResponse
	results []protocol.AppResult
}

func (c *fakeClient) FetchApp(context.Context, string, int) (protocol.AppVersionResponse, error) {
	return c.version, nil
}

func (c *fakeClient) ReportAppResult(_ context.Context, _ string, r protocol.AppResult) error {
	c.results = append(c.results, r)
	return nil
}

func newSyncer(t *testing.T, c *fakeClient, w apps.Winget) (*apps.Syncer, *state.Store) {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &apps.Syncer{
		State: st, Client: c, Winget: w, Now: func() time.Time { return now },
	}, st
}

func item(id string, version int, o protocol.AppOptions) protocol.Item {
	raw, err := o.Marshal()
	if err != nil {
		panic(err)
	}
	return protocol.Item{Kind: protocol.ItemKindApp, ID: id, Version: version, Options: raw}
}

// A missing app is detected and then installed, and the result says which
// version landed.
func TestInstallsWhatIsMissing(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if got := w.ran(); len(got) < 2 || got[0] != "detect" || got[1] != "install" {
		t.Fatalf("it should detect then install, got %v", got)
	}
	if len(c.results) != 1 {
		t.Fatalf("one result should be reported, got %+v", c.results)
	}
	if c.results[0].Status != protocol.ResultSucceeded || c.results[0].InstalledVersion != "26.03" {
		t.Errorf("result = %+v", c.results[0])
	}
}

// Something already installed is not installed again, and nothing is reported:
// there is no news.
func TestLeavesAnInstalledAppAlone(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installed: true, version: "26.03"}
	s, _ := newSyncer(t, c, w)

	it := item("a1", 1, opts(nil))
	if err := s.Sync(context.Background(), []protocol.Item{it}); err != nil {
		t.Fatal(err)
	}
	// A second cycle immediately afterwards does not even detect again.
	if err := s.Sync(context.Background(), []protocol.Item{it}); err != nil {
		t.Fatal(err)
	}
	for _, call := range w.ran() {
		if call == "install" {
			t.Fatalf("it must not reinstall what is present, got %v", w.ran())
		}
	}
	if len(w.ran()) != 1 {
		t.Errorf("the second cycle should not detect again within the hour, got %v", w.ran())
	}
}

// Uninstall intent removes it and reports that it went.
func TestUninstallIntentRemovesIt(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installed: true, version: "26.03"}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, uninstall())}); err != nil {
		t.Fatal(err)
	}
	if len(c.results) != 1 || c.results[0].Intent != protocol.IntentUninstall {
		t.Fatalf("an uninstall should be reported as one, got %+v", c.results)
	}
	if c.results[0].Status != protocol.ResultSucceeded {
		t.Errorf("result = %+v", c.results[0])
	}
}

// A failed install is reported as failed, with the exit code, and the app is
// not recorded as installed.
func TestReportsAFailedInstall(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{installErr: 1}
	s, st := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if len(c.results) != 1 || c.results[0].Status != protocol.ResultFailed {
		t.Fatalf("a failed install should be reported as one, got %+v", c.results)
	}
	if c.results[0].ExitCode != 1 {
		t.Errorf("the exit code should survive, got %+v", c.results[0])
	}
	local, err := st.AppState("a1")
	if err != nil {
		t.Fatal(err)
	}
	if local.Installed {
		t.Error("a failed install must not be remembered as installed")
	}
	if local.Failures != 1 {
		t.Errorf("failures = %d, want 1", local.Failures)
	}
}

// A failed detection is not an answer, only a failed attempt to get one:
// treating it as "the app is absent" would make the agent reinstall software
// on every cycle for as long as winget or the package source is unreachable.
// Nothing must be installed, nothing reported, and nothing remembered as
// having changed.
func TestFailedDetectionDoesNotInstall(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{detectErr: errors.New("winget list: source unreachable")}
	s, st := newSyncer(t, c, w)

	before, err := st.AppState("a1")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}

	for _, call := range w.ran() {
		if call == "install" {
			t.Fatalf("a failed detection must never trigger an install, got %v", w.ran())
		}
	}
	if len(c.results) != 0 {
		t.Fatalf("a failed detection is not a result, got %+v", c.results)
	}
	after, err := st.AppState("a1")
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("local state must not change on a failed detection: before=%+v after=%+v", before, after)
	}
	if after.Failures != 0 {
		t.Errorf("failures = %d, want 0", after.Failures)
	}
	if after.Installed {
		t.Error("a failed detection must not flip Installed")
	}
}

// The confirmatory detect that runs after a successful install is only there
// to learn the version string; if it fails, the install itself must still be
// reported as a success, just with InstalledVersion left empty.
func TestInstallSucceedsEvenIfTheVersionCheckFails(t *testing.T) {
	c := &fakeClient{version: protocol.AppVersionResponse{
		Version: 1, PackageID: "7zip.7zip", Scope: "machine",
	}}
	w := &fakeWinget{
		detectErr: errors.New("winget list: source unreachable"),
		// The first detect (before the install) must succeed and report the
		// app absent; only the second one, right after installing, fails.
		detectFailFrom: 2,
	}
	s, _ := newSyncer(t, c, w)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}

	if got := w.ran(); len(got) < 2 || got[0] != "detect" || got[1] != "install" {
		t.Fatalf("it should detect then install, got %v", got)
	}
	if len(c.results) != 1 {
		t.Fatalf("one result should be reported, got %+v", c.results)
	}
	if c.results[0].Status != protocol.ResultSucceeded {
		t.Errorf("a failed version check must not turn a successful install into a failure, got %+v", c.results[0])
	}
	if c.results[0].InstalledVersion != "" {
		t.Errorf("installed version = %q, want empty since the version check failed", c.results[0].InstalledVersion)
	}
}

// An item of another kind is ignored, which is how an older agent copes with a
// newer server.
func TestIgnoresOtherKinds(t *testing.T) {
	c := &fakeClient{}
	w := &fakeWinget{}
	s, _ := newSyncer(t, c, w)

	err := s.Sync(context.Background(), []protocol.Item{{Kind: "script", ID: "s1", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.ran()) != 0 {
		t.Fatalf("nothing should have happened, got %v", w.ran())
	}
}
