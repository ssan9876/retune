package apps_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// versionsClient serves each version of one app from a map.
type versionsClient struct {
	versions map[int]protocol.AppVersionResponse
	results  []protocol.AppResult
}

func (c *versionsClient) FetchApp(_ context.Context, _ string, version int) (protocol.AppVersionResponse, error) {
	v, ok := c.versions[version]
	if !ok {
		return v, fmt.Errorf("no version %d", version)
	}
	return v, nil
}

func (c *versionsClient) ReportAppResult(_ context.Context, _ string, r protocol.AppResult) error {
	c.results = append(c.results, r)
	return nil
}

// fakeInstaller stands in for Packages: installed tracks which version is
// "on the machine", as a detection rule for that version would see it.
type fakeInstaller struct {
	mu            sync.Mutex
	installed     map[int]bool
	uninstallExit int
	log           []string
}

func (f *fakeInstaller) Detect(_ context.Context, _ string, v protocol.AppVersionResponse) (bool, string, apps.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed[v.Version], "", apps.Result{}
}

func (f *fakeInstaller) Install(_ context.Context, _ string, v protocol.AppVersionResponse) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, fmt.Sprintf("install %d", v.Version))
	f.installed[v.Version] = true
	return apps.Result{}
}

func (f *fakeInstaller) Uninstall(_ context.Context, _ string, v protocol.AppVersionResponse) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, fmt.Sprintf("uninstall %d", v.Version))
	if f.uninstallExit == 0 {
		delete(f.installed, v.Version)
	}
	return apps.Result{ExitCode: f.uninstallExit}
}

func (f *fakeInstaller) Outcome(_ protocol.AppVersionResponse, code int) apps.Outcome {
	if code == 0 {
		return apps.OutcomeSucceeded
	}
	return apps.OutcomeFailed
}

func pkg(version int, uninstallPrevious bool) protocol.AppVersionResponse {
	return protocol.AppVersionResponse{
		Version: version, Source: protocol.AppSourcePackage, InstallerType: protocol.InstallerMSI,
		FileName: "a.msi", UninstallPrevious: uninstallPrevious,
	}
}

func packageSyncer(t *testing.T, c apps.Client, inst apps.Installer) (*apps.Syncer, *state.Store) {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &apps.Syncer{
		State: st, Client: c, Packages: inst,
		// No App Installer on this machine: packages must still work.
		Unavailable: apps.ErrNoAppInstaller,
		Now:         func() time.Time { return now },
	}, st
}

func TestPackageInstallsWithoutWinget(t *testing.T) {
	c := &versionsClient{versions: map[int]protocol.AppVersionResponse{1: pkg(1, false)}}
	inst := &fakeInstaller{installed: map[int]bool{}}
	s, st := packageSyncer(t, c, inst)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if len(inst.log) != 1 || inst.log[0] != "install 1" {
		t.Fatalf("installer did %v", inst.log)
	}
	if len(c.results) != 1 || c.results[0].Status != protocol.ResultSucceeded {
		t.Fatalf("results = %+v", c.results)
	}
	got, _ := st.AppState("a1")
	if got.InstalledByAgent != 1 {
		t.Errorf("InstalledByAgent = %d, want 1", got.InstalledByAgent)
	}

	// A winget app on the same machine is still reported unavailable.
	c.versions[1] = protocol.AppVersionResponse{Version: 1, PackageID: "7zip.7zip", Scope: "machine"}
	if err := s.Sync(context.Background(), []protocol.Item{item("w1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if last := c.results[len(c.results)-1]; last.Status != protocol.ResultFailed || last.Detail != apps.ErrNoAppInstaller.Error() {
		t.Errorf("winget app = %+v", last)
	}
}

func TestPackagesUnavailableIsReportedOnce(t *testing.T) {
	c := &versionsClient{versions: map[int]protocol.AppVersionResponse{1: pkg(1, false)}}
	s, _ := packageSyncer(t, c, nil)
	s.Packages, s.PackagesUnavailable = nil, errors.New("uploaded MSI and EXE packages install only on Windows")
	for range 2 {
		if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.results) != 1 || c.results[0].Detail != s.PackagesUnavailable.Error() {
		t.Fatalf("results = %+v", c.results)
	}
}

func TestUpgradeRemovesThePreviousVersionFirst(t *testing.T) {
	c := &versionsClient{versions: map[int]protocol.AppVersionResponse{1: pkg(1, false), 2: pkg(2, true)}}
	inst := &fakeInstaller{installed: map[int]bool{}}
	s, st := packageSyncer(t, c, inst)

	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 2, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	want := []string{"install 1", "uninstall 1", "install 2"}
	if fmt.Sprint(inst.log) != fmt.Sprint(want) {
		t.Fatalf("installer did %v, want %v", inst.log, want)
	}
	if got, _ := st.AppState("a1"); got.InstalledByAgent != 2 {
		t.Errorf("InstalledByAgent = %d, want 2", got.InstalledByAgent)
	}
}

func TestUpgradeStopsIfRemovingThePreviousVersionFails(t *testing.T) {
	c := &versionsClient{versions: map[int]protocol.AppVersionResponse{1: pkg(1, false), 2: pkg(2, true)}}
	inst := &fakeInstaller{installed: map[int]bool{}}
	s, _ := packageSyncer(t, c, inst)
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	inst.uninstallExit = 1603
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 2, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(inst.log) != fmt.Sprint([]string{"install 1", "uninstall 1"}) {
		t.Fatalf("installer did %v; it must not install over a failed removal", inst.log)
	}
	last := c.results[len(c.results)-1]
	if last.Status != protocol.ResultFailed || last.Version != 2 {
		t.Fatalf("result = %+v", last)
	}
}

func TestUpgradeLeavesWhatTheAgentDidNotInstall(t *testing.T) {
	// Version 1 was already on the machine when the app was first assigned:
	// detected, never installed by the agent, so never removed by it.
	c := &versionsClient{versions: map[int]protocol.AppVersionResponse{1: pkg(1, false), 2: pkg(2, true)}}
	inst := &fakeInstaller{installed: map[int]bool{1: true}}
	s, _ := packageSyncer(t, c, inst)
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 1, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), []protocol.Item{item("a1", 2, opts(nil))}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(inst.log) != fmt.Sprint([]string{"install 2"}) {
		t.Fatalf("installer did %v", inst.log)
	}
}
