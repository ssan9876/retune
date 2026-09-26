package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"retune/internal/config"
	"retune/internal/release"
	"retune/internal/server/app"
	"retune/internal/server/store"
	"retune/internal/serverupdate"
	"retune/internal/version"
)

type serverBody struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
	Note    string `json:"mode_note"`
	Latest  *struct {
		Version string `json:"version"`
		Notes   string `json:"notes"`
	} `json:"latest"`
	UpdateAvailable   bool                `json:"update_available"`
	State             *serverupdate.State `json:"state"`
	PendingApprovalID string              `json:"pending_approval_id"`
}

// releaseFeed serves one signed release the way the GitHub API does, with a
// server binary for this machine's architecture.
func releaseFeed(t *testing.T, ver string) *httptest.Server {
	t.Helper()
	serverBin := []byte("the server, version " + ver)
	sum := sha256.Sum256(serverBin)
	serverName := "retune-server-linux-" + runtime.GOARCH
	m := release.ReleaseManifest{
		Schema: release.ManifestSchema, Version: ver, PublishedAt: time.Now().UTC(), Notes: "What changed in " + ver,
		Assets: []release.Asset{{Name: serverName, Kind: release.AssetServer, OS: "linux", Arch: runtime.GOARCH,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(serverBin))}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.SignReleaseManifest(testReleaseKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, _ := json.Marshal(sig)
	files := map[string][]byte{"release.json": raw, "release.json.sig": sigRaw, serverName: serverBin}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases" {
			var assets []map[string]string
			for name := range files {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": srv.URL + "/dl/" + name})
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"tag_name": "v" + ver, "published_at": time.Now().UTC(), "assets": assets,
			}})
			return
		}
		b, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// updateApp is a server in binary-update mode that has found release 1.2.0.
func updateApp(t *testing.T, adjust func(*config.Server)) (*app.App, *httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	a, srv := newTestAppWith(t, func(c *config.Server) {
		feed := releaseFeed(t, "1.2.0")
		c.ReleaseFeed = config.ReleaseFeedConfig{Enabled: true, URL: feed.URL + "/releases", Interval: time.Hour}
		c.ServerUpdate = config.ServerUpdateConfig{Mode: config.ServerUpdateBinary, Dir: dir}
		if adjust != nil {
			adjust(c)
		}
	})
	// The release has no agent builds, so the import step complains; the
	// release is recorded all the same.
	_ = a.ReleaseFeed.CheckNow(context.Background())
	if _, err := a.Store.Q().GetReleaseByVersion(context.Background(), "1.2.0"); err != nil {
		t.Fatalf("the feed did not record the release: %v", err)
	}
	return a, srv, dir
}

func setVersion(t *testing.T, v string) {
	old := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = old })
}

func TestServerUpdateThroughTheAPI(t *testing.T) {
	setVersion(t, "1.1.0")
	a, srv, dir := updateApp(t, nil)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := admin.do(http.MethodGet, "/server", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /server: %d %s", status, body)
	}
	got := decodeJSON[serverBody](t, body)
	if got.Version != "1.1.0" || got.Latest == nil || got.Latest.Version != "1.2.0" || !got.UpdateAvailable || got.Mode != "binary" {
		t.Fatalf("GET /server = %+v", got)
	}

	// Read-only admins can see the version, not update.
	viewer := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := viewer.do(http.MethodGet, "/server", nil); status != http.StatusOK {
		t.Fatalf("read-only GET: %d", status)
	}
	if status, _ := viewer.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"}); status != http.StatusForbidden {
		t.Fatalf("read-only update: %d, want 403", status)
	}

	// Only the newest verified release.
	if status, body := admin.do(http.MethodPost, "/server/update", map[string]any{"version": "9.9.9"}); status != http.StatusConflict {
		t.Fatalf("an unknown version: %d %s", status, body)
	}

	status, body = admin.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"})
	if status != http.StatusAccepted {
		t.Fatalf("update: %d %s", status, body)
	}
	var req serverupdate.ApplyRequest
	b, err := os.ReadFile(filepath.Join(dir, serverupdate.RequestFile))
	if err != nil || json.Unmarshal(b, &req) != nil || req.Version != "1.2.0" || req.RequestedBy == "" {
		t.Fatalf("the staged request = %s (%v)", b, err)
	}
	if staged, err := os.ReadFile(req.Staged); err != nil || string(staged) != "the server, version 1.2.0" {
		t.Fatalf("the staged binary = %q (%v)", staged, err)
	}
	for _, f := range []string{"release.json", "release.json.sig"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(req.Staged), f)); err != nil {
			t.Fatalf("%s should be staged beside the binary: %v", f, err)
		}
	}

	_, body = admin.do(http.MethodGet, "/server", nil)
	if st := decodeJSON[serverBody](t, body).State; st == nil || st.Phase != serverupdate.PhaseQueued {
		t.Fatalf("state after the request = %+v", st)
	}
	// One at a time.
	if status, body := admin.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"}); status != http.StatusConflict {
		t.Fatalf("a second update while one waits: %d %s", status, body)
	}
	entries, _, err := a.Store.Q().ListAuditPage(context.Background(), store.AuditFilter{Action: "server.update_started", Page: store.Page{Limit: 10}})
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit = %v (%v)", entries, err)
	}
}

// The server is never downgraded, or "updated" to itself.
func TestServerUpdateRefusesDowngrades(t *testing.T) {
	setVersion(t, "1.2.0")
	a, srv, _ := updateApp(t, nil)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, body := admin.do(http.MethodGet, "/server", nil)
	if decodeJSON[serverBody](t, body).UpdateAvailable {
		t.Fatal("the same version is no update")
	}
	if status, body := admin.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"}); status != http.StatusConflict {
		t.Fatalf("reinstalling the running version: %d %s", status, body)
	}
}

// With nothing to apply an update, the console says why and refuses.
func TestServerUpdateWithoutAnUpdater(t *testing.T) {
	setVersion(t, "1.1.0")
	a, srv, _ := updateApp(t, func(c *config.Server) {
		c.ServerUpdate = config.ServerUpdateConfig{Mode: config.ServerUpdateAuto, UpdaterSocket: filepath.Join(t.TempDir(), "none.sock")}
	})
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, body := admin.do(http.MethodGet, "/server", nil)
	got := decodeJSON[serverBody](t, body)
	if got.Mode != "none" || got.Note == "" || !got.UpdateAvailable {
		t.Fatalf("GET /server = %+v", got)
	}
	if status, body := admin.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"}); status != http.StatusConflict {
		t.Fatalf("update with no updater: %d %s", status, body)
	}
}

// With approvals on, an update waits for a second administrator, and runs
// when they approve it.
func TestServerUpdateWaitsForApproval(t *testing.T) {
	setVersion(t, "1.1.0")
	a, srv, dir := updateApp(t, func(c *config.Server) {
		c.Approvals = config.ApprovalsConfig{Required: true, DeviceThreshold: 50}
	})
	first := signedIn(t, a, srv, store.RoleAdmin)
	seedAdmin(t, a, "second@example.com", testPassword, store.RoleAdmin)
	second := newAdminClient(t, a, srv)
	if status, body := second.login("second@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}

	status, body := first.do(http.MethodPost, "/server/update", map[string]any{"version": "1.2.0"})
	if status != http.StatusAccepted {
		t.Fatalf("update: %d %s", status, body)
	}
	approval := decodeJSON[struct {
		Approval struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"approval"`
	}](t, body).Approval
	if approval.Kind != store.ApprovalServerUpdate {
		t.Fatalf("held as %q", approval.Kind)
	}
	if _, err := os.Stat(filepath.Join(dir, serverupdate.RequestFile)); !os.IsNotExist(err) {
		t.Fatal("nothing should be staged before approval")
	}
	_, body = first.do(http.MethodGet, "/server", nil)
	if decodeJSON[serverBody](t, body).PendingApprovalID != approval.ID {
		t.Fatalf("the pending approval should show: %s", body)
	}
	if status, _ := first.do(http.MethodPost, "/approvals/"+approval.ID+"/approve", map[string]any{"reason": "mine"}); status == http.StatusOK {
		t.Fatal("nobody approves their own request")
	}
	status, body = second.do(http.MethodPost, "/approvals/"+approval.ID+"/approve", map[string]any{"reason": "release notes look fine"})
	if status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, body)
	}
	if _, err := os.Stat(filepath.Join(dir, serverupdate.RequestFile)); err != nil {
		t.Fatalf("approving should stage the update: %v", err)
	}
}
