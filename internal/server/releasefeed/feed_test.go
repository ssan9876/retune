package releasefeed_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/release"
	"retune/internal/server/agentversions"
	"retune/internal/server/artifacts"
	"retune/internal/server/releasefeed"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// feedServer plays GitHub: a release list, and the files each release
// publishes. Tests change what it serves as they go.
type feedServer struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	// releases, in the order the list shows them.
	releases []served
}

type served struct {
	version    string
	prerelease bool
	files      map[string][]byte
}

func newFeedServer(t *testing.T) *feedServer {
	f := &feedServer{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /releases", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}
		var out []map[string]any
		for _, rel := range f.releases {
			var assets []asset
			for name := range rel.files {
				assets = append(assets, asset{Name: name, URL: f.srv.URL + "/dl/" + rel.version + "/" + name})
			}
			out = append(out, map[string]any{
				"tag_name": "v" + rel.version, "prerelease": rel.prerelease, "draft": false,
				"published_at": time.Now().UTC().Format(time.RFC3339), "assets": assets,
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /dl/{version}/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, rel := range f.releases {
			if rel.version == r.PathValue("version") {
				if b, ok := rel.files[r.PathValue("name")]; ok {
					_, _ = w.Write(b)
					return
				}
			}
		}
		http.NotFound(w, r)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *feedServer) publish(rel served) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases = append([]served{rel}, f.releases...)
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// releaseAgents are the agent builds a test release publishes: one per kind
// of machine, named as the release workflow names them.
var releaseAgents = []struct{ file, goos, goarch string }{
	{"retune-agent.exe", "windows", "amd64"},
	{"retune-agent-darwin-universal", "darwin", "universal"},
	{"retune-agent-linux-amd64", "linux", "amd64"},
}

// buildRelease makes the files a release publishes: an agent per platform
// with its signature, and release.json with its signature, signed by key.
func buildRelease(t *testing.T, key release.PrivateKey, version string, prerelease bool) served {
	t.Helper()
	files := map[string][]byte{}
	m := release.ReleaseManifest{
		Schema: release.ManifestSchema, Version: version, Prerelease: prerelease,
		PublishedAt: time.Now().UTC().Truncate(time.Second), Notes: "notes for " + version,
	}
	for _, a := range releaseAgents {
		agent := []byte(a.file + " " + version)
		agentSig, err := json.Marshal(release.Sign(key, release.Manifest{Version: version, SHA256: hexSum(agent)}))
		if err != nil {
			t.Fatal(err)
		}
		files[a.file], files[a.file+".sig"] = agent, agentSig
		m.Assets = append(m.Assets,
			release.Asset{Name: a.file, Kind: release.AssetAgent, OS: a.goos, Arch: a.goarch, SHA256: hexSum(agent), Size: int64(len(agent))},
			release.Asset{Name: a.file + ".sig", Kind: release.AssetSignature, SHA256: hexSum(agentSig), Size: int64(len(agentSig))},
		)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.SignReleaseManifest(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, _ := json.Marshal(sig)
	files["release.json"], files["release.json.sig"] = raw, sigRaw
	return served{version: version, prerelease: prerelease, files: files}
}

type fixture struct {
	st     *store.Store
	key    release.PrivateKey
	server *feedServer
	feed   *releasefeed.Service
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.New(t)
	f := &fixture{st: st, key: key, server: newFeedServer(t), now: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	keys := []release.PublicKey{key.Public()}
	f.feed = &releasefeed.Service{
		Store:  st,
		Source: releasefeed.GitHub{URL: f.server.srv.URL + "/releases"},
		Keys:   keys,
		Agents: &agentversions.Service{Store: st, Artifacts: artifacts.Store{Dir: t.TempDir()}, ReleaseKeys: keys},
		Now:    func() time.Time { return f.now },
	}
	return f
}

func TestPollVerifiesAndImportsOnce(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.server.publish(buildRelease(t, f.key, "1.2.0", false))

	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	rel, err := f.st.Q().GetReleaseByVersion(ctx, "1.2.0")
	if err != nil {
		t.Fatalf("release not recorded: %v", err)
	}
	if rel.AgentVersionID == nil || rel.ImportError != "" || rel.Notes != "notes for 1.2.0" {
		t.Fatalf("release = %+v", rel)
	}
	v, err := f.st.Q().GetAgentVersionByVersion(ctx, "1.2.0")
	if err != nil || v.Source != store.SourceReleaseFeed || v.ID != *rel.AgentVersionID {
		t.Fatalf("imported version = %+v, %v", v, err)
	}
	// Every platform's build joins the one version.
	builds, err := f.st.Q().ListAgentVersionBuilds(ctx, []uuid.UUID{v.ID})
	if err != nil {
		t.Fatal(err)
	}
	var platforms []string
	for _, b := range builds[v.ID] {
		platforms = append(platforms, b.Platform)
	}
	if strings.Join(platforms, ",") != "darwin-universal,linux-amd64,windows-amd64" {
		t.Fatalf("builds = %v", platforms)
	}

	// A second check changes nothing.
	n, err := f.feed.Poll(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second poll: n=%d err=%v", n, err)
	}
	all, _, _ := f.st.Q().ListAgentVersions(ctx, store.Page{})
	if len(all) != 1 {
		t.Fatalf("want one build, have %d", len(all))
	}
	state, _ := f.st.Q().GetReleaseFeedState(ctx)
	if state.CheckedAt == nil || state.Error != "" {
		t.Fatalf("feed state = %+v", state)
	}

	// Latest re-verifies what was stored.
	latest, m, err := f.feed.Latest(ctx)
	if err != nil || latest.Version != "1.2.0" || m.Version != "1.2.0" {
		t.Fatalf("latest = %v %v %v", latest.Version, m.Version, err)
	}
}

// An upload of the same build before the feed got to it is not a conflict.
func TestImportAcceptsTheSameBuildAlreadyUploaded(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rel := buildRelease(t, f.key, "1.2.0", false)
	if _, err := f.feed.Agents.Upload(ctx, agentversions.NewVersion{
		Version: "1.2.0", Actor: "admin@example.com",
		SignatureHeader: b64(rel.files["retune-agent.exe.sig"]),
	}, strings.NewReader(string(rel.files["retune-agent.exe"]))); err != nil {
		t.Fatal(err)
	}
	f.server.publish(rel)
	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	got, _ := f.st.Q().GetReleaseByVersion(ctx, "1.2.0")
	if got.AgentVersionID == nil {
		t.Fatal("the release should point at the uploaded build")
	}
}

func TestPollRefusesAManifestFromAnotherKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	stranger, _ := release.GenerateKey()
	f.server.publish(buildRelease(t, stranger, "1.2.0", false))

	if _, err := f.feed.Poll(ctx); !errors.Is(err, release.ErrUntrustedKey) {
		t.Fatalf("want an untrusted-key error, got %v", err)
	}
	if _, err := f.st.Q().GetReleaseByVersion(ctx, "1.2.0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unverified release must not be recorded: %v", err)
	}
	state, _ := f.st.Q().GetReleaseFeedState(ctx)
	if !strings.Contains(state.Error, "did not verify") {
		t.Fatalf("the failure should be recorded, got %q", state.Error)
	}
}

// Bytes that don't match the manifest are refused. The release is not marked
// imported until every platform's build is in; the next check imports only
// what is missing.
func TestPollRefusesAnAgentThatDoesNotMatchTheManifest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rel := buildRelease(t, f.key, "1.2.0", false)
	good := rel.files["retune-agent-linux-amd64"]
	rel.files["retune-agent-linux-amd64"] = []byte("something else entirely")
	f.server.publish(rel)

	if _, err := f.feed.Poll(ctx); err == nil || !strings.Contains(err.Error(), "linux-amd64") {
		t.Fatalf("mismatched agent bytes must be refused, naming the platform: %v", err)
	}
	got, err := f.st.Q().GetReleaseByVersion(ctx, "1.2.0")
	if err != nil {
		t.Fatalf("the verified release itself is still recorded: %v", err)
	}
	if got.AgentVersionID != nil || got.ImportError == "" {
		t.Fatalf("release = %+v", got)
	}
	v, err := f.st.Q().GetAgentVersionByVersion(ctx, "1.2.0")
	if err != nil {
		t.Fatalf("the good builds are in: %v", err)
	}
	if _, err := f.st.Q().GetAgentVersionBuild(ctx, v.ID, "linux-amd64"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no linux build should exist: %v", err)
	}

	// The download is fixed: the next check brings in just the missing build.
	f.server.mu.Lock()
	f.server.releases[0].files["retune-agent-linux-amd64"] = good
	f.server.mu.Unlock()
	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ = f.st.Q().GetReleaseByVersion(ctx, "1.2.0"); got.AgentVersionID == nil || got.ImportError != "" {
		t.Fatalf("release = %+v", got)
	}
	if _, err := f.st.Q().GetAgentVersionBuild(ctx, v.ID, "linux-amd64"); err != nil {
		t.Fatalf("linux build: %v", err)
	}
}

// A tampered build signature is caught by the manifest's hash of it.
func TestPollRefusesATamperedBuildSignature(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rel := buildRelease(t, f.key, "1.2.0", false)
	rel.files["retune-agent.exe.sig"] = append(rel.files["retune-agent.exe.sig"], ' ')
	f.server.publish(rel)
	if _, err := f.feed.Poll(ctx); err == nil || !strings.Contains(err.Error(), "hashes to") {
		t.Fatalf("want a hash mismatch, got %v", err)
	}
}

func TestPollNeverGoesBackwards(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.server.publish(buildRelease(t, f.key, "1.2.0", false))
	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	// The list now shows only an older release: it is ignored.
	f.server.mu.Lock()
	f.server.releases = nil
	f.server.mu.Unlock()
	f.server.publish(buildRelease(t, f.key, "1.1.0", false))
	if n, err := f.feed.Poll(ctx); err != nil || n != 0 {
		t.Fatalf("older release: n=%d err=%v", n, err)
	}
	if _, err := f.st.Q().GetReleaseByVersion(ctx, "1.1.0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an older release must not be recorded")
	}
}

func TestPrereleasesOnlyWhenAllowed(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.server.publish(buildRelease(t, f.key, "1.2.0", false))
	f.server.publish(buildRelease(t, f.key, "1.3.0-rc.1", true))

	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Q().GetReleaseByVersion(ctx, "1.3.0-rc.1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a prerelease must be ignored by default")
	}
	if _, err := f.st.Q().GetReleaseByVersion(ctx, "1.2.0"); err != nil {
		t.Fatalf("the newest release should be taken instead: %v", err)
	}

	f.feed.AllowPrerelease = true
	if _, err := f.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Q().GetReleaseByVersion(ctx, "1.3.0-rc.1"); err != nil {
		t.Fatalf("with prereleases allowed it is taken: %v", err)
	}
}

func TestPollWithoutKeysSaysSo(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.feed.Keys = nil
	if _, err := f.feed.Poll(ctx); !errors.Is(err, releasefeed.ErrNoKeys) {
		t.Fatalf("want ErrNoKeys, got %v", err)
	}
}

func TestCheckNowRefusesWhileAnotherCheckRuns(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = f.st.WithAdvisoryLock(ctx, releasefeed.LockID, func(*store.Queries) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	defer close(release)
	if err := f.feed.CheckNow(ctx); !errors.Is(err, releasefeed.ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
}
