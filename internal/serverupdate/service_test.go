package serverupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/server/releasefeed"
)

const testToken = "0123456789abcdef-token"

// blockingEnv holds an update in Backup until released, so a second request
// arrives while one is running.
type blockingEnv struct {
	fakeEnv
	release chan struct{}
}

func (e *blockingEnv) Backup(ctx context.Context, name string) (string, error) {
	<-e.release
	return e.fakeEnv.Backup(ctx, name)
}

func newService(t *testing.T, env Env, raw, sig []byte, f fixture) *Service {
	t.Helper()
	svc := &Service{Token: testToken, States: FileStore{Path: filepath.Join(t.TempDir(), "state.json")}}
	svc.Updater = &Updater{Env: env, Fetch: fakeFetch{raw: raw, sig: sig}, Keys: f.keys, Save: svc.States.Save}
	return svc
}

func post(h http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUpdaterServiceNeedsTheToken(t *testing.T) {
	f := newFixture(t)
	svc := newService(t, &fakeEnv{current: "1.1.0"}, nil, nil, f)
	for _, tok := range []string{"", "wrong-token-wrong-token"} {
		if rec := post(svc.Handler(), tok, `{"id":"u1","version":"1.2.0"}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: %d, want 401", tok, rec.Code)
		}
	}
	svc.Token = ""
	if rec := post(svc.Handler(), "", `{"id":"u1","version":"1.2.0"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("an updater without a token must refuse everything, got %d", rec.Code)
	}
}

func TestUpdaterServiceRunsOneUpdateAtATime(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	env := &blockingEnv{fakeEnv: fakeEnv{current: "1.1.0"}, release: make(chan struct{})}
	svc := newService(t, env, raw, sig, f)
	h := svc.Handler()
	if rec := post(h, testToken, `{"id":"u1","version":"1.2.0"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	if rec := post(h, testToken, `{"id":"u2","version":"1.2.0"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second while the first runs: %d, want 409", rec.Code)
	}
	close(env.release)
	deadline := time.Now().Add(5 * time.Second)
	for svc.Busy() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got stateEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.State == nil || got.State.Phase != PhaseHealthy {
		t.Fatalf("status = %s (%v)", rec.Body, err)
	}
}

func TestUpdaterRecoversFromARestartMidUpdate(t *testing.T) {
	svc := &Service{States: FileStore{Path: filepath.Join(t.TempDir(), "state.json")}}
	if err := svc.States.Save(State{ID: "u1", Version: "1.2.0", Phase: PhasePulling}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Recover(); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.States.Load()
	if st.Phase != PhaseFailed || !strings.Contains(st.Error, "restarted") || st.FinishedAt == nil {
		t.Fatalf("state = %+v", st)
	}
}

// The server and the updater, end to end over a real unix socket.
func TestSocketClientTalksToTheUpdater(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	svc := newService(t, &fakeEnv{current: "1.1.0"}, raw, sig, f)
	sock := filepath.Join(t.TempDir(), "u.sock")
	l, err := ListenUnix(sock)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	srv := &http.Server{Handler: svc.Handler()}
	go srv.Serve(l)
	defer srv.Close()

	ctx := context.Background()
	c := SocketClient{Path: sock, Token: testToken}
	if err := c.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, Request{ID: "u1", Version: "1.2.0"}, Staged{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := c.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st != nil && st.Done() {
			if st.Phase != PhaseHealthy {
				t.Fatalf("state = %+v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the update never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	bad := SocketClient{Path: sock, Token: "not-the-token-at-all"}
	if err := bad.Start(ctx, Request{ID: "u2", Version: "1.2.0"}, Staged{}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong token: %v", err)
	}
	if err := (SocketClient{Path: sock}).Ready(); err == nil {
		t.Fatal("a client with no token is not ready")
	}
}

// fakeSource is a release feed listing one release.
type fakeSource struct {
	version string
	files   map[string][]byte
}

func (s fakeSource) List(context.Context) ([]releasefeed.Candidate, error) {
	c := releasefeed.Candidate{Version: s.version, Assets: map[string]string{}}
	for name := range s.files {
		c.Assets[name] = "https://feed.example/" + name
	}
	return []releasefeed.Candidate{c}, nil
}

func (s fakeSource) Open(_ context.Context, url string) (io.ReadCloser, error) {
	b, ok := s.files[strings.TrimPrefix(url, "https://feed.example/")]
	if !ok {
		return nil, errors.New("404 " + url)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func TestFeedFetcherFindsTheVersion(t *testing.T) {
	src := fakeSource{version: "1.2.0", files: map[string][]byte{ManifestFile: []byte("m"), SignatureFile: []byte("s")}}
	raw, sig, err := FeedFetcher{Source: src}.Fetch(context.Background(), "v1.2.0")
	if err != nil || string(raw) != "m" || string(sig) != "s" {
		t.Fatalf("Fetch = %q %q %v", raw, sig, err)
	}
	if _, _, err := (FeedFetcher{Source: src}).Fetch(context.Background(), "1.3.0"); err == nil {
		t.Fatal("a version the feed does not list")
	}
}

// A binary install, end to end: the server stages the release, update-apply
// verifies and swaps it, and the state says how it went.
func TestBinaryStagingAndApply(t *testing.T) {
	f := newFixture(t)
	raw, sig := f.manifest(t, "1.2.0")
	ctx := context.Background()
	m, err := Verify(f.keys, raw, sig, "1.2.0", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	updates := t.TempDir()
	src := fakeSource{version: "1.2.0", files: map[string][]byte{
		"retune-server-linux-amd64": f.server, ManifestFile: raw, SignatureFile: sig,
	}}
	c := BinaryClient{Dir: updates, Source: src, GOARCH: "amd64"}
	req := Request{ID: "u1", Version: "1.2.0", RequestedBy: "a@example.com", RequestedAt: time.Now()}
	if err := c.Start(ctx, req, Staged{Manifest: m, Raw: raw, Signature: sig}); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(ctx); st == nil || st.Phase != PhaseQueued || st.ID != "u1" {
		t.Fatalf("before update-apply runs: %+v", st)
	}
	if err := c.Start(ctx, req, Staged{Manifest: m, Raw: raw, Signature: sig}); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second request while one waits: %v", err)
	}

	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ready.Close()
	bin := t.TempDir()
	installed := filepath.Join(bin, "retune-server")
	_ = os.WriteFile(installed, []byte("old"), 0o755)
	r := &fakeRunner{answers: map[string]string{installed + " version": "1.1.0\n"}}
	env := &Binary{Run: r, BinaryPath: installed, Unit: "retune-server", ReadyURL: ready.URL, HTTP: ready.Client(),
		BackupDir: filepath.Join(bin, "backups"), DatabaseURL: "postgres://retune@localhost/retune", GOARCH: "amd64", Poll: time.Millisecond}
	st, ran, err := ApplyStaged(ctx, updates, env, f.keys, nil)
	if err != nil || !ran {
		t.Fatalf("ApplyStaged = %v, %v", ran, err)
	}
	if st.Phase != PhaseHealthy {
		t.Fatalf("state = %+v", st)
	}
	if got, _ := os.ReadFile(installed); string(got) != string(f.server) {
		t.Fatalf("installed = %q", got)
	}
	if _, err := os.Stat(filepath.Join(updates, RequestFile)); !os.IsNotExist(err) {
		t.Fatal("the request should be consumed")
	}
	if got, _ := c.Status(ctx); got == nil || got.Phase != PhaseHealthy {
		t.Fatalf("status after = %+v", got)
	}
	if _, ran, err := ApplyStaged(ctx, updates, env, f.keys, nil); ran || err != nil {
		t.Fatalf("with nothing waiting: %v %v", ran, err)
	}
}

// A request naming a binary outside the update directory is refused: the
// root-run applier only ever installs what the server staged.
func TestApplyRefusesAStagedPathOutsideItsDirectory(t *testing.T) {
	updates := t.TempDir()
	if err := writeJSONAtomic(filepath.Join(updates, RequestFile),
		ApplyRequest{Request: Request{ID: "u1", Version: "1.2.0"}, Staged: "/usr/bin/evil"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := ApplyStaged(context.Background(), updates, &Binary{}, newFixture(t).keys, nil)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("ApplyStaged = %v", err)
	}
}
