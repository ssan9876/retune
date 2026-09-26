package serverupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"retune/internal/release"
	"retune/internal/server/releasefeed"
)

// The ways a server can be updated.
const (
	ModeDocker = "docker"
	ModeBinary = "binary"
	ModeNone   = "none"
)

// Staged is the verified release an update is for, as the server recorded it.
type Staged struct {
	Manifest  release.ReleaseManifest
	Raw       []byte
	Signature []byte
}

// Client is how a server hands an update to whatever applies it.
type Client interface {
	// Mode is ModeDocker or ModeBinary.
	Mode() string
	// Ready says whether updates can be applied now, and if not, why.
	Ready() error
	// Start hands over one update. It returns ErrBusy while one is running.
	Start(ctx context.Context, req Request, rel Staged) error
	// Status is the latest update's state, or nil if there has never been one.
	Status(ctx context.Context) (*State, error)
}

// SocketClient talks to the retune-updater service over its unix socket.
type SocketClient struct {
	Path  string
	Token string
}

// Mode is ModeDocker.
func (c SocketClient) Mode() string { return ModeDocker }

// Ready checks the socket is there and a token is set.
func (c SocketClient) Ready() error {
	if c.Token == "" {
		return errors.New("UPDATER_TOKEN is not set")
	}
	if _, err := os.Stat(c.Path); err != nil {
		return fmt.Errorf("the updater is not running (no socket at %s)", c.Path)
	}
	return nil
}

func (c SocketClient) client() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.Path)
		}},
	}
}

func (c SocketClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://updater"+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	return c.client().Do(req)
}

// Start asks the updater to update. The updater fetches and verifies the
// release itself: only the version travels.
func (c SocketClient) Start(ctx context.Context, req Request, _ Staged) error {
	res, err := c.do(ctx, http.MethodPost, "/update", req)
	if err != nil {
		return fmt.Errorf("reach the updater: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusConflict:
		return ErrBusy
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
	return fmt.Errorf("the updater answered %s: %s", res.Status, strings.TrimSpace(string(b)))
}

// Status asks the updater how the latest update went.
func (c SocketClient) Status(ctx context.Context) (*State, error) {
	res, err := c.do(ctx, http.MethodGet, "/status", nil)
	if err != nil {
		return nil, fmt.Errorf("reach the updater: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the updater answered %s", res.Status)
	}
	var env stateEnvelope
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&env); err != nil {
		return nil, err
	}
	return env.State, nil
}

// BinaryClient stages an update for `retune-server update-apply`, which a
// systemd path unit starts, as root, when the request file appears.
type BinaryClient struct {
	// Dir is where updates are staged: DIR/request.json, DIR/state.json and
	// DIR/<version>/.
	Dir    string
	Source releasefeed.Source
	GOARCH string
}

// ApplyRequest is DIR/request.json: what update-apply is asked to do.
type ApplyRequest struct {
	Request
	// Staged is the downloaded binary.
	Staged string `json:"staged"`
}

// RequestFile, StateFile are the files in the update directory.
const (
	RequestFile = "request.json"
	StateFile   = "state.json"
)

// Mode is ModeBinary.
func (c BinaryClient) Mode() string { return ModeBinary }

// Ready checks the update directory can be written.
func (c BinaryClient) Ready() error {
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return fmt.Errorf("the update directory %s cannot be created: %w", c.Dir, err)
	}
	return nil
}

// Start downloads the release's server binary, checks it against the
// manifest, and writes the request that sets update-apply off. The request is
// written last, so the path unit never sees a half-staged update.
func (c BinaryClient) Start(ctx context.Context, req Request, rel Staged) error {
	if st, _ := c.Status(ctx); st != nil && !st.Done() {
		return ErrBusy
	}
	arch := c.GOARCH
	if arch == "" {
		arch = runtime.GOARCH
	}
	asset, ok := rel.Manifest.Find(release.AssetServer, "linux", arch)
	if !ok {
		return fmt.Errorf("release %s publishes no server for linux/%s", rel.Manifest.Version, arch)
	}
	cand, err := FindCandidate(ctx, c.Source, rel.Manifest.Version)
	if err != nil {
		return err
	}
	url := cand.Assets[asset.Name]
	if url == "" {
		return fmt.Errorf("the release feed lists no download for %s", asset.Name)
	}
	dir := filepath.Join(c.Dir, safe(rel.Manifest.Version))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	staged := filepath.Join(dir, "retune-server")
	if err := c.fetch(ctx, url, staged, asset.SHA256); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), rel.Raw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, SignatureFile), rel.Signature, 0o644); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(c.Dir, RequestFile), ApplyRequest{Request: req, Staged: staged})
}

func (c BinaryClient) fetch(ctx context.Context, url, path, want string) error {
	body, err := c.Source.Open(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(path+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, 512<<20)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		os.Remove(path + ".part")
		return fmt.Errorf("the downloaded server hashes to %s, not the manifest's %s", got, want)
	}
	return os.Rename(path+".part", path)
}

// Status reads how the latest update went. A request update-apply has not
// picked up yet shows as queued.
func (c BinaryClient) Status(_ context.Context) (*State, error) {
	st, err := FileStore{Path: filepath.Join(c.Dir, StateFile)}.Load()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(c.Dir, RequestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var req ApplyRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	if st != nil && st.ID == req.ID {
		return st, nil
	}
	return &State{ID: req.ID, Version: req.Version, RequestedBy: req.RequestedBy, Phase: PhaseQueued,
		StartedAt: req.RequestedAt, UpdatedAt: req.RequestedAt}, nil
}
