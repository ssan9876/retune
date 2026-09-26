package serverupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/release"
)

// fixture is a release signed by a key the test trusts.
type fixture struct {
	priv   release.PrivateKey
	keys   []release.PublicKey
	server []byte // the linux/amd64 server binary the manifest names
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return fixture{priv: priv, keys: []release.PublicKey{priv.Public()}, server: []byte("new server binary")}
}

// manifest returns a signed release.json for version and its sidecar.
func (f fixture) manifest(t *testing.T, version string) (raw, sig []byte) {
	t.Helper()
	sum := sha256.Sum256(f.server)
	m := release.ReleaseManifest{
		Schema: release.ManifestSchema, Version: version, PublishedAt: time.Unix(1700000000, 0).UTC(), Notes: "notes",
		Assets: []release.Asset{
			{Name: "retune-server-linux-amd64", Kind: release.AssetServer, OS: "linux", Arch: "amd64",
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.server))},
			{Name: "server-image", Kind: release.AssetServerImage, Image: "ghcr.io/example/retune-server",
				Digest: "sha256:" + strings.Repeat("ab", 32)},
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s, err := release.SignReleaseManifest(f.priv, raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

type fakeFetch struct {
	raw, sig []byte
	err      error
}

func (f fakeFetch) Fetch(context.Context, string) ([]byte, []byte, error) { return f.raw, f.sig, f.err }

// fakeEnv records what an update did and fails where told to.
type fakeEnv struct {
	current                      string
	backupErr, stageErr, swapErr error
	healthErrs                   []error // one per WaitHealthy call, then nil
	restoreErr                   error
	calls                        []string
	staged                       string
}

func (e *fakeEnv) Current(context.Context) (string, error) {
	e.calls = append(e.calls, "current")
	return e.current, nil
}
func (e *fakeEnv) Backup(_ context.Context, name string) (string, error) {
	e.calls = append(e.calls, "backup")
	return "/backups/" + name + ".dump", e.backupErr
}
func (e *fakeEnv) Stage(_ context.Context, m release.ReleaseManifest) (string, error) {
	e.calls = append(e.calls, "stage")
	img, _ := m.ServerImage()
	e.staged = img.Image + "@" + img.Digest
	return e.staged, e.stageErr
}
func (e *fakeEnv) Swap(_ context.Context, target string) (string, error) {
	e.calls = append(e.calls, "swap "+target)
	return "previous", e.swapErr
}
func (e *fakeEnv) WaitHealthy(context.Context) error {
	e.calls = append(e.calls, "health")
	if len(e.healthErrs) == 0 {
		return nil
	}
	err := e.healthErrs[0]
	e.healthErrs = e.healthErrs[1:]
	return err
}
func (e *fakeEnv) Restore(_ context.Context, previous string) error {
	e.calls = append(e.calls, "restore "+previous)
	return e.restoreErr
}

func (e *fakeEnv) did(call string) bool {
	for _, c := range e.calls {
		if strings.HasPrefix(c, call) {
			return true
		}
	}
	return false
}

func run(t *testing.T, env *fakeEnv, fetch Fetcher, keys []release.PublicKey, version string) (State, []string) {
	t.Helper()
	var phases []string
	u := &Updater{Env: env, Fetch: fetch, Keys: keys, Save: func(s State) error {
		phases = append(phases, s.Phase)
		return nil
	}}
	return u.Run(context.Background(), Request{ID: "u1", Version: version, RequestedBy: "a@example.com"}), phases
}

func TestUpdateSucceeds(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &fakeEnv{current: "1.1.0"}
	st, phases := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
	if st.Phase != PhaseHealthy || st.Error != "" {
		t.Fatalf("state = %+v", st)
	}
	want := []string{PhaseQueued, PhaseVerifying, PhaseBackingUp, PhasePulling, PhaseRestarting, PhaseHealthy}
	if strings.Join(phases, ",") != strings.Join(want, ",") {
		t.Fatalf("phases = %v, want %v", phases, want)
	}
	if st.FromVersion != "1.1.0" || !strings.Contains(st.Backup, "retune-1.1.0-to-1.2.0-") || st.FinishedAt == nil {
		t.Fatalf("state = %+v", st)
	}
	if !env.did("swap ghcr.io/example/retune-server@sha256:abab") {
		t.Fatalf("it should install the image by the manifest's digest: %v", env.calls)
	}
}

// Nothing is touched for a release that does not verify: not the database,
// not the running server.
func TestUpdateRefusesWhatDoesNotVerify(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	other := newFixture(t)
	tampered := []byte(strings.Replace(string(raw), `"notes"`, `"evil"`, 1))
	for name, c := range map[string]struct {
		fetch Fetcher
		keys  []release.PublicKey
		ver   string
		want  string
	}{
		"tampered manifest": {fakeFetch{raw: tampered, sig: sig}, f.keys, "1.2.0", "did not verify"},
		"untrusted key":     {fakeFetch{raw: raw, sig: sig}, other.keys, "1.2.0", "did not verify"},
		"another version":   {fakeFetch{raw: raw, sig: sig}, f.keys, "1.3.0", "manifest is for 1.2.0"},
		"unreachable feed":  {fakeFetch{err: errors.New("no route")}, f.keys, "1.2.0", "no route"},
		"garbled signature": {fakeFetch{raw: raw, sig: []byte("{")}, f.keys, "1.2.0", "release.json.sig"},
	} {
		t.Run(name, func(t *testing.T) {
			env := &fakeEnv{current: "1.1.0"}
			st, _ := run(t, env, c.fetch, c.keys, c.ver)
			if st.Phase != PhaseFailed || !strings.Contains(st.Error, c.want) {
				t.Fatalf("state = %+v, want failed with %q", st, c.want)
			}
			if env.did("backup") || env.did("swap") {
				t.Fatalf("nothing should have been done: %v", env.calls)
			}
		})
	}
}

// The server is never downgraded, and never "updated" to what it runs.
func TestUpdateRefusesDowngrades(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	for _, current := range []string{"1.2.0", "1.3.0", "2.0.0-rc.1"} {
		env := &fakeEnv{current: current}
		st, _ := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
		if st.Phase != PhaseFailed || !strings.Contains(st.Error, ErrNotNewer.Error()) {
			t.Errorf("from %s: state = %+v", current, st)
		}
		if env.did("backup") {
			t.Errorf("from %s: it should stop before the backup", current)
		}
	}
}

// A development build is older than any release.
func TestNewerThanADevelopmentBuild(t *testing.T) {
	for _, c := range []struct {
		candidate, current string
		want               bool
	}{
		{"1.0.0", "0.0.0-dev", true},
		{"1.0.0", "", true},
		{"1.0.0", "garbage", true},
		{"1.0.1", "1.0.0", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.0-rc.1", "1.0.0", false},
		{"1.0.0", "1.0.0-rc.1", true},
		{"0.9.9", "1.0.0", false},
	} {
		if got := Newer(c.candidate, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.candidate, c.current, got, c.want)
		}
	}
}

func TestUpdateStopsWhenTheBackupFails(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &fakeEnv{current: "1.1.0", backupErr: errors.New("disk full")}
	st, _ := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
	if st.Phase != PhaseFailed || !strings.Contains(st.Error, "disk full") || env.did("stage") || env.did("swap") {
		t.Fatalf("state = %+v, calls = %v", st, env.calls)
	}
}

func TestUpdateRollsBackWhenTheNewServerIsUnhealthy(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &fakeEnv{current: "1.1.0", healthErrs: []error{errors.New("the new server is unhealthy")}}
	st, _ := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
	if st.Phase != PhaseRolledBack || !strings.Contains(st.Error, "unhealthy") {
		t.Fatalf("state = %+v", st)
	}
	if !env.did("restore previous") {
		t.Fatalf("it should have put the previous build back: %v", env.calls)
	}
}

func TestUpdateRollsBackWhenTheSwapFails(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &fakeEnv{current: "1.1.0", swapErr: errors.New("compose up failed")}
	st, _ := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
	if st.Phase != PhaseRolledBack || !env.did("restore previous") {
		t.Fatalf("state = %+v, calls = %v", st, env.calls)
	}
}

func TestUpdateReportsAFailedRollback(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &fakeEnv{current: "1.1.0", healthErrs: []error{errors.New("unhealthy")}, restoreErr: errors.New("image gone")}
	st, _ := run(t, env, fakeFetch{raw: raw, sig: sig}, f.keys, "1.2.0")
	if st.Phase != PhaseFailed || !strings.Contains(st.Error, "rolling back also failed: image gone") {
		t.Fatalf("state = %+v", st)
	}
}
